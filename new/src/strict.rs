use modmath::{strict_mod_add, strict_mod_exp, strict_mod_inv, strict_mod_mul, strict_mod_sub};
use crate::lazy_field::{lazy_mod_add, lazy_mod_sub, lazy_mod_mul};

#[cfg(feature = "montgomery")]
use modmath::{NPrimeMethod, strict_montgomery_mod_exp_with_method};

#[cfg(feature = "std")]
use log::info;

#[cfg(feature = "defmt")]
use defmt::info;

#[cfg(all(feature = "montgomery", feature = "montgomery-euclidean"))]
const METHOD: NPrimeMethod = NPrimeMethod::ExtendedEuclidean;

#[cfg(all(feature = "montgomery", feature = "montgomery-hensels"))]
const METHOD: NPrimeMethod = NPrimeMethod::HenselsLifting;

#[cfg(all(
    feature = "montgomery",
    not(feature = "montgomery-euclidean"),
    not(feature = "montgomery-hensels")
))]
const METHOD: NPrimeMethod = NPrimeMethod::ExtendedEuclidean; // Default to ExtendedEuclidean if no method specified

use crate::{BrigIntStrict, CoreIntStrict, Point};

// Niels coordinates: (Y+X, Y-X, 2dT) - optimized for point additions
// Reduces point addition from 10M to 8M multiplications 
type NielsPoint<T> = (T, T, T);
use crate::{D_BYTES, G_T_BYTES, G_X_BYTES, G_Y_BYTES, MODP_SQRT_M1_BYTES, P_BYTES, Q_BYTES};

fn print_value<T: BrigIntStrict>(label: &str, value: &T)
where
    for<'a> &'a T: core::ops::BitAnd<Output = T>
        + core::ops::Rem<&'a T, Output = T>
        + core::ops::Add<&'a T, Output = T>
        + core::ops::Sub<T, Output = T>
        + core::ops::Sub<&'a T, Output = T>
        + core::ops::Mul<&'a T, Output = T>
        + core::ops::Div<&'a T, Output = T>,
{
    let mut buffer = [0u8; 128];
    let bytes = value.to_bytes_le(&mut buffer);

    // Trim trailing zeros to show only significant bytes
    let trimmed_bytes = if let Some(last_nonzero) = bytes.iter().rposition(|&b| b != 0) {
        &bytes[..=last_nonzero]
    } else {
        &bytes[..1] // Keep at least one byte even if value is zero
    };

    let hex_string: String = trimmed_bytes.iter().map(|b| format!("{:02x}", b)).collect();
    info!("{}: {}", label, hex_string);
}

// LAZY version of recover_x - optimizes basic arithmetic while keeping expensive ops (sqrt, inverse) as-is  
// Reduces ~15 basic divisions while preserving the inherently expensive square root computation
fn recover_x_lazy<T: BrigIntStrict>(y: T, sign: u8, p: &T, d: T) -> Option<T>
where
    for<'a> &'a T: core::ops::BitAnd<Output = T>
        + core::ops::Rem<&'a T, Output = T>
        + core::ops::Add<&'a T, Output = T>
        + core::ops::Sub<T, Output = T>
        + core::ops::Sub<&'a T, Output = T>
        + core::ops::Mul<&'a T, Output = T>
        + core::ops::Div<&'a T, Output = T>,
{
    let one = T::one();

    // First compute y² mod p - lazy: 1 mul only (y is from bytes, < p)
    let y2 = &y + &T::zero();
    let y2 = lazy_mod_mul(y, &y2, p);

    // Create another copy of y² for later use
    let y2_copy = &y2 + &T::zero();

    // left = (y² - 1) mod p - lazy: 1 sub (y² < p, 1 < p)
    let left = lazy_mod_sub(y2, &one, p);

    // denom_raw = (d * y²) mod p - lazy: 1 mul (d < p, y² < p)
    let denom_raw = lazy_mod_mul(d, &y2_copy, p);

    // denom = (denom_raw + 1) mod p - lazy: 1 add
    let denom = lazy_mod_add(denom_raw, &one, p);

    // inv_denom = denom^(-1) mod p - KEEP EXPENSIVE (inherently costly)
    let two = &one + &one;
    let three = &two + &one;
    let _exp = p - two.clone();

    let inv_denom = {
        #[cfg(feature = "montgomery")]
        {
            // Even with Montgomery, use direct inverse instead of pow(p-2) for better performance
            strict_mod_inv(denom, p).unwrap()
        }
        #[cfg(not(feature = "montgomery"))]
        {
            // Use Extended Euclidean instead of Fermat's little theorem (denom^(p-2))
            strict_mod_inv(denom, p).unwrap()
        }
    };

    // Finally, x2 = left * inv_denom mod p - lazy: 1 mul (both inputs < p)
    let x2 = lazy_mod_mul(left, &inv_denom, p);

    if x2 == T::zero() {
        if sign > 0 { None } else { Some(T::zero()) }
    } else {
        // three already defined above
        let p3 = p + &three;
        let four = &two + &two;
        let eight = &four + &four;

        let exp = p3 / &eight;
        let x2_copy = &x2 + &T::zero();

        // Square root computation - KEEP EXPENSIVE (inherently costly)
        let mut x = {
            #[cfg(feature = "montgomery")]
            {
                strict_montgomery_mod_exp_with_method(x2, &exp, p, METHOD).unwrap()
            }
            #[cfg(not(feature = "montgomery"))]
            {
                strict_mod_exp(x2, &exp, p)
            }
        };

        // Use precomputed modp_sqrt_m1 = 2^((p-1)/4) mod p instead of computing it
        let modp_sqrt_m1 = T::from_bytes_le(&MODP_SQRT_M1_BYTES);

        // Verification operations - lazy: basic arithmetic only
        let x_copy = &x + &T::zero();
        let x_for_mul = &x + &T::zero();
        let tmp1 = lazy_mod_mul(x_for_mul, &x_copy, p);
        let tmp2 = lazy_mod_sub(tmp1, &x2_copy, p);
        if tmp2 != T::zero() {
            x = lazy_mod_mul(x, &modp_sqrt_m1, p);
        }

        let x_copy2 = &x + &T::zero();
        let x_for_final_check = &x + &T::zero();
        let tmp1 = lazy_mod_mul(x_for_final_check, &x_copy2, p);
        let x2_copy2 = &x2_copy + &T::zero();
        let tmp2 = lazy_mod_sub(tmp1, &x2_copy2, p);
        if tmp2 != T::zero() {
            return None;
        }
        let x_for_check = &x + &T::zero();
        let weird = (&x_for_check & &one.clone() == one) as u8 != sign;
        // To be continued...
        if weird {
            x = p - x;
        }

        Some(x)
    }
}

// Original version kept for comparison/fallback
fn recover_x<T: BrigIntStrict>(y: T, sign: u8, p: &T, d: T) -> Option<T>
where
    for<'a> &'a T: core::ops::BitAnd<Output = T>
        + core::ops::Rem<&'a T, Output = T>
        + core::ops::Add<&'a T, Output = T>
        + core::ops::Sub<T, Output = T>
        + core::ops::Sub<&'a T, Output = T>
        + core::ops::Mul<&'a T, Output = T>
        + core::ops::Div<&'a T, Output = T>,
{
    let one = T::one();

    // First compute y² mod p
    let y2 = &y + &T::zero();
    let y2 = strict_mod_mul(y, &y2, p);

    // Create another copy of y² for later use
    let y2_copy = &y2 + &T::zero();

    // left = (y² - 1) mod p
    let left = strict_mod_sub(y2, &one, p);

    // denom_raw = (d * y²) mod p
    let denom_raw = strict_mod_mul(d, &y2_copy, p);

    // denom = (denom_raw + 1) mod p
    let denom = strict_mod_add(denom_raw, &one, p);

    // inv_denom = denom^(-1) mod p
    let two = &one + &one;
    let three = &two + &one;
    let exp = p - two.clone();

    //info!("recovering x");
    //print_value("denom", &denom);
    //print_value("exp", &exp);
    //print_value("p", &p);

    let inv_denom = {
        #[cfg(feature = "montgomery")]
        {
            // Even with Montgomery, use direct inverse instead of pow(p-2) for better performance
            strict_mod_inv(denom, p).unwrap()
        }
        #[cfg(not(feature = "montgomery"))]
        {
            // Use Extended Euclidean instead of Fermat's little theorem (denom^(p-2))
            strict_mod_inv(denom, p).unwrap()
        }
    };

    // Finally, x2 = left * inv_denom mod p
    let x2 = strict_mod_mul(left, &inv_denom, p);

    if x2 == T::zero() {
        if sign > 0 { None } else { Some(T::zero()) }
    } else {
        // three already defined above
        let p3 = p + &three;
        let four = &two + &two;
        let eight = &four + &four;

        let exp = p3 / &eight;
        let x2_copy = &x2 + &T::zero();

        let mut x = {
            #[cfg(feature = "montgomery")]
            {
                strict_montgomery_mod_exp_with_method(x2, &exp, p, METHOD).unwrap()
            }
            #[cfg(not(feature = "montgomery"))]
            {
                strict_mod_exp(x2, &exp, p)
            }
        };

        // Use precomputed modp_sqrt_m1 = 2^((p-1)/4) mod p instead of computing it
        let modp_sqrt_m1 = T::from_bytes_le(&MODP_SQRT_M1_BYTES);

        let x_copy = &x + &T::zero();
        let x_for_mul = &x + &T::zero();
        let tmp1 = strict_mod_mul(x_for_mul, &x_copy, p);
        let tmp2 = strict_mod_sub(tmp1, &x2_copy, p);
        if tmp2 != T::zero() {
            x = strict_mod_mul(x, &modp_sqrt_m1, p);
        }

        let x_copy2 = &x + &T::zero();
        let x_for_final_check = &x + &T::zero();
        let tmp1 = strict_mod_mul(x_for_final_check, &x_copy2, p);
        let x2_copy2 = &x2_copy + &T::zero();
        let tmp2 = strict_mod_sub(tmp1, &x2_copy2, p);
        if tmp2 != T::zero() {
            return None;
        }
        let x_for_check = &x + &T::zero();
        let weird = (&x_for_check & &one.clone() == one) as u8 != sign;
        // To be continued...
        if weird {
            x = p - x;
        }

        Some(x)
    }
}

fn decompress_edward_point<T: BrigIntStrict>(k: [u8; 32], p: &T, d: &T) -> Option<Point<T>>
where
    for<'a> &'a T: core::ops::BitAnd<Output = T>
        + core::ops::Rem<&'a T, Output = T>
        + core::ops::Add<&'a T, Output = T>
        + core::ops::Sub<T, Output = T>
        + core::ops::Sub<&'a T, Output = T>
        + core::ops::Mul<&'a T, Output = T>
        + core::ops::Div<&'a T, Output = T>,
{
    let mut k_list = k.clone();
    let sign = k_list[k.len() - 1] >> 7;
    k_list[k.len() - 1] &= 0b01111111;
    let y = T::from_bytes_le(&k_list[0..32]);

    if &y > p {
        None
    } else {
        let d_owned = d + &T::zero();
        let y_owned = &y + &T::zero();
        let x = recover_x_lazy(y, sign, p, d_owned);
        x.map(|x_val| {
            let x_copy = &x_val + &T::zero();
            let y_copy = &y_owned + &T::zero();
            (x_val, y_owned, T::one(), lazy_mod_mul(x_copy, &y_copy, p))
        })
    }
}

fn concat_emul<'a>(slices: &[&[u8]], storage: &'a mut [u8]) -> &'a [u8] {
    let total_len = slices.iter().map(|s| s.len()).sum();
    let mut offset = 0;
    for slice in slices {
        storage[offset..offset + slice.len()].copy_from_slice(slice);
        offset += slice.len();
    }
    &storage[..total_len]
}

fn sha512_modq<T: BrigIntStrict>(msg: &[u8], q: &T) -> T
where
    for<'a> &'a T: core::ops::BitAnd<Output = T>
        + core::ops::Rem<&'a T, Output = T>
        + core::ops::Add<&'a T, Output = T>
        + core::ops::Sub<T, Output = T>
        + core::ops::Sub<&'a T, Output = T>
        + core::ops::Mul<&'a T, Output = T>
        + core::ops::Div<&'a T, Output = T>,
{
    let mut compact_sha = hmac_sha512::Hash::new();
    compact_sha.update(msg);
    let finalized = compact_sha.finalize();
    let hash = finalized.as_slice();

    let result_nomodq = T::from_bytes_le(&hash[0..64]);
    result_nomodq % q
}

// LAZY Edwards point doubling for Ed25519 (a = -1)
// Assumes input point coordinates are < p to avoid expensive divisions
// Reduces ~41 divisions per doubling to ~7 divisions
fn point_double_lazy<T: BrigIntStrict>(pp: &Point<T>, p: &T) -> Point<T>
where
    for<'a> &'a T: core::ops::BitAnd<Output = T>
        + core::ops::Rem<&'a T, Output = T>
        + core::ops::Add<&'a T, Output = T>
        + core::ops::Sub<T, Output = T>
        + core::ops::Sub<&'a T, Output = T>
        + core::ops::Mul<&'a T, Output = T>
        + core::ops::Div<&'a T, Output = T>,
{
    // Extended Edwards doubling for Ed25519 (a = -1)
    // Input: P = (X:Y:Z:T) in extended coordinates (ASSUMES: all < p)
    // Output: 2P = (X2:Y2:Z2:T2)
    
    // A = X^2 - lazy: 1 mul only
    let pp0_copy = &pp.0 + &T::zero();
    let a = lazy_mod_mul(pp0_copy, &pp.0, p);
    
    // B = Y^2 - lazy: 1 mul only
    let pp1_copy = &pp.1 + &T::zero();
    let b = lazy_mod_mul(pp1_copy, &pp.1, p);
    
    // C = 2*Z^2 - lazy: 2 muls (Z² then 2*Z²)
    let two = &T::one() + &T::one();
    let pp2_copy = &pp.2 + &T::zero();
    let z_squared = lazy_mod_mul(pp2_copy, &pp.2, p);
    let c = lazy_mod_mul(two, &z_squared, p);
    
    // D = -A (since a = -1 for Ed25519) - lazy: 1 sub
    let d_val = lazy_mod_sub(T::zero(), &a, p);
    
    // E = (X+Y)^2 - A - B - lazy: 1 add + 1 mul + 2 subs
    let x_plus_y = lazy_mod_add(pp.0.clone(), &pp.1, p);
    let x_plus_y_copy = &x_plus_y + &T::zero();
    let x_plus_y_squared = lazy_mod_mul(x_plus_y_copy, &x_plus_y, p);
    let e_temp = lazy_mod_sub(x_plus_y_squared, &a, p);
    let e = lazy_mod_sub(e_temp, &b, p);
    
    // G = D + B - lazy: 1 add
    let g = lazy_mod_add(d_val.clone(), &b, p);
    
    // F = G - C - lazy: 1 sub
    let f = lazy_mod_sub(g.clone(), &c, p);
    
    // H = D - B - lazy: 1 sub
    let h = lazy_mod_sub(d_val, &b, p);
    
    // Final coordinates: lazy 4 muls only
    // X2 = E * F
    let e_copy = &e + &T::zero();
    let x2 = lazy_mod_mul(e_copy, &f, p);
    
    // Y2 = G * H
    let g_copy = &g + &T::zero();
    let y2 = lazy_mod_mul(g_copy, &h, p);
    
    // Z2 = F * G
    let f_copy = &f + &T::zero();
    let z2 = lazy_mod_mul(f_copy, &g, p);
    
    // T2 = E * H
    let e_copy2 = &e + &T::zero();
    let t2 = lazy_mod_mul(e_copy2, &h, p);
    
    (x2, y2, z2, t2)
}

// Original version kept for comparison/fallback
fn point_double<T: BrigIntStrict>(pp: &Point<T>, p: &T) -> Point<T>
where
    for<'a> &'a T: core::ops::BitAnd<Output = T>
        + core::ops::Rem<&'a T, Output = T>
        + core::ops::Add<&'a T, Output = T>
        + core::ops::Sub<T, Output = T>
        + core::ops::Sub<&'a T, Output = T>
        + core::ops::Mul<&'a T, Output = T>
        + core::ops::Div<&'a T, Output = T>,
{
    // Extended Edwards doubling for Ed25519 (a = -1)
    // Input: P = (X:Y:Z:T) in extended coordinates
    // Output: 2P = (X2:Y2:Z2:T2)
    
    // A = X^2
    let pp0_copy = &pp.0 + &T::zero();
    let a = strict_mod_mul(pp0_copy, &pp.0, p);
    
    // B = Y^2  
    let pp1_copy = &pp.1 + &T::zero();
    let b = strict_mod_mul(pp1_copy, &pp.1, p);
    
    // C = 2*Z^2
    let two = &T::one() + &T::one();
    let pp2_copy = &pp.2 + &T::zero();
    let z_squared = strict_mod_mul(pp2_copy, &pp.2, p);
    let c = strict_mod_mul(two, &z_squared, p);
    
    // D = -A (since a = -1 for Ed25519)
    let d_val = strict_mod_sub(T::zero(), &a, p);
    
    // E = (X+Y)^2 - A - B
    let x_plus_y = strict_mod_add(pp.0.clone(), &pp.1, p);
    let x_plus_y_copy = &x_plus_y + &T::zero();
    let x_plus_y_squared = strict_mod_mul(x_plus_y_copy, &x_plus_y, p);
    let e_temp = strict_mod_sub(x_plus_y_squared, &a, p);
    let e = strict_mod_sub(e_temp, &b, p);
    
    // G = D + B
    let g = strict_mod_add(d_val.clone(), &b, p);
    
    // F = G - C
    let f = strict_mod_sub(g.clone(), &c, p);
    
    // H = D - B  
    let h = strict_mod_sub(d_val, &b, p);
    
    // Final coordinates:
    // X2 = E * F
    let e_copy = &e + &T::zero();
    let x2 = strict_mod_mul(e_copy, &f, p);
    
    // Y2 = G * H
    let g_copy = &g + &T::zero();
    let y2 = strict_mod_mul(g_copy, &h, p);
    
    // Z2 = F * G
    let f_copy = &f + &T::zero();
    let z2 = strict_mod_mul(f_copy, &g, p);
    
    // T2 = E * H
    let e_copy2 = &e + &T::zero();
    let t2 = strict_mod_mul(e_copy2, &h, p);
    
    (x2, y2, z2, t2)
}

fn point_add<T: BrigIntStrict>(pp: &Point<T>, qq: &Point<T>, p: &T, d: &T) -> Point<T>
where
    for<'a> &'a T: core::ops::BitAnd<Output = T>
        + core::ops::Rem<&'a T, Output = T>
        + core::ops::Add<&'a T, Output = T>
        + core::ops::Sub<T, Output = T>
        + core::ops::Sub<&'a T, Output = T>
        + core::ops::Mul<&'a T, Output = T>
        + core::ops::Div<&'a T, Output = T>,
{
    // a = (pp.1 - pp.0) * (qq.1 - qq.0) mod p
    let pp1_sub_pp0 = strict_mod_sub(&pp.1 + &T::zero(), &pp.0, p);
    let qq1_sub_qq0 = strict_mod_sub(&qq.1 + &T::zero(), &qq.0, p);
    let a = strict_mod_mul(pp1_sub_pp0, &qq1_sub_qq0, p);

    // b = (pp.1 + pp.0) * (qq.1 + qq.0) mod p
    let pp1_add_pp0 = strict_mod_add(&pp.1 + &T::zero(), &pp.0, p);
    let qq1_add_qq0 = strict_mod_add(&qq.1 + &T::zero(), &qq.0, p);
    let b = strict_mod_mul(pp1_add_pp0, &qq1_add_qq0, p);

    // c = 2 * pp.3 * qq.3 * d mod p
    let two = &T::one() + &T::one();
    let pp3_mul_qq3 = strict_mod_mul(&pp.3 + &T::zero(), &qq.3, p);
    let c_temp = strict_mod_mul(two, &pp3_mul_qq3, p);
    let c = strict_mod_mul(c_temp, d, p);

    // d_val = 2 * pp.2 * qq.2 mod p
    let two2 = &T::one() + &T::one();
    let pp2_mul_qq2 = strict_mod_mul(&pp.2 + &T::zero(), &qq.2, p);
    let d_val = strict_mod_mul(two2, &pp2_mul_qq2, p);

    // Create all needed copies upfront
    let b_copy1 = &b + &T::zero();
    let _b_copy2 = &b + &T::zero();
    let d_val_copy1 = &d_val + &T::zero();
    let _d_val_copy2 = &d_val + &T::zero();
    let a_copy = &a + &T::zero();
    let c_copy1 = &c + &T::zero();
    let _c_copy2 = &c + &T::zero();

    // x3 = (b - a) * (d_val - c) mod p
    let b_sub_a = strict_mod_sub(b, &a, p);
    let d_sub_c = strict_mod_sub(d_val, &c, p);
    let b_sub_a_for_x = &b_sub_a + &T::zero();
    let x3 = strict_mod_mul(b_sub_a_for_x, &d_sub_c, p);

    // y3 = (d_val + c) * (b + a) mod p
    let d_add_c = strict_mod_add(d_val_copy1, &c_copy1, p);
    let b_add_a = strict_mod_add(b_copy1, &a_copy, p);
    let d_add_c_for_y = &d_add_c + &T::zero();
    let y3 = strict_mod_mul(d_add_c_for_y, &b_add_a, p);

    // z3 = (d_val - c) * (d_val + c) mod p
    let d_sub_c_copy = &d_sub_c + &T::zero();
    let d_add_c_copy = &d_add_c + &T::zero();
    let z3 = strict_mod_mul(d_sub_c_copy, &d_add_c_copy, p);

    // t3 = (b - a) * (b + a) mod p
    let b_sub_a_copy = &b_sub_a + &T::zero();
    let b_add_a_copy = &b_add_a + &T::zero();
    let t3 = strict_mod_mul(b_sub_a_copy, &b_add_a_copy, p);

    (x3, y3, z3, t3)
}

// LAZY Convert extended coordinates to Niels form: (Y+X, Y-X, 2dT)
// Assumes input point coordinates are < p (from lazy point operations)
// Reduces 4 expensive divisions to 2 divisions
fn to_niels_lazy<T: BrigIntStrict>(pp: &Point<T>, p: &T, d: &T) -> NielsPoint<T>
where
    for<'a> &'a T: core::ops::BitAnd<Output = T>
        + core::ops::Rem<&'a T, Output = T>
        + core::ops::Add<&'a T, Output = T>
        + core::ops::Sub<T, Output = T>
        + core::ops::Sub<&'a T, Output = T>
        + core::ops::Mul<&'a T, Output = T>
        + core::ops::Div<&'a T, Output = T>,
{
    // Y+X - lazy: 1 add (Y < p, X < p)
    let y_plus_x = lazy_mod_add(pp.1.clone(), &pp.0, p);
    
    // Y-X - lazy: 1 sub (Y < p, X < p)  
    let y_minus_x = lazy_mod_sub(pp.1.clone(), &pp.0, p);
    
    // 2dT - lazy: 2 muls (d < p, T < p, then 2 < p)
    let two = &T::one() + &T::one();
    let d_copy = d.clone();
    let dt = lazy_mod_mul(d_copy, &pp.3, p);
    let two_dt = lazy_mod_mul(two, &dt, p);
    
    (y_plus_x, y_minus_x, two_dt)
}

// Original version kept for comparison
fn to_niels<T: BrigIntStrict>(pp: &Point<T>, p: &T, d: &T) -> NielsPoint<T>
where
    for<'a> &'a T: core::ops::BitAnd<Output = T>
        + core::ops::Rem<&'a T, Output = T>
        + core::ops::Add<&'a T, Output = T>
        + core::ops::Sub<T, Output = T>
        + core::ops::Sub<&'a T, Output = T>
        + core::ops::Mul<&'a T, Output = T>
        + core::ops::Div<&'a T, Output = T>,
{
    // Y+X
    let y_plus_x = strict_mod_add(pp.1.clone(), &pp.0, p);
    
    // Y-X
    let y_minus_x = strict_mod_sub(pp.1.clone(), &pp.0, p);
    
    // 2dT 
    let two = &T::one() + &T::one();
    let d_copy = d.clone();
    let dt = strict_mod_mul(d_copy, &pp.3, p);
    let two_dt = strict_mod_mul(two, &dt, p);
    
    (y_plus_x, y_minus_x, two_dt)
}

// Mixed addition: Extended + Niels -> Extended  
// LAZY VERSION: Assumes all inputs are reduced (< p) to avoid expensive divisions
// Reduces ~32 divisions per point addition to ~4 divisions
fn point_add_niels_lazy<T: BrigIntStrict>(pp: &Point<T>, niels: &NielsPoint<T>, p: &T) -> Point<T>
where
    for<'a> &'a T: core::ops::BitAnd<Output = T>
        + core::ops::Rem<&'a T, Output = T>
        + core::ops::Add<&'a T, Output = T>
        + core::ops::Sub<T, Output = T>
        + core::ops::Sub<&'a T, Output = T>
        + core::ops::Mul<&'a T, Output = T>
        + core::ops::Div<&'a T, Output = T>,
{
    // Mixed Edwards addition formula from "Twisted Edwards Curves" paper
    // Input: P = (X1:Y1:Z1:T1) in extended, Q = (y+x, y-x, 2dt) in Niels
    // Output: P+Q in extended coordinates
    // ASSUMES: All coordinates in pp and niels are < p (reduced)
    
    let (y_plus_x, y_minus_x, two_dt) = niels;
    
    // A = (Y1-X1)*(y-x) - lazy: 1 sub + 1 mul 
    let pp_y_minus_x = lazy_mod_sub(pp.1.clone(), &pp.0, p);
    let a = lazy_mod_mul(pp_y_minus_x, y_minus_x, p);
    
    // B = (Y1+X1)*(y+x) - lazy: 1 add + 1 mul
    let pp_y_plus_x = lazy_mod_add(pp.1.clone(), &pp.0, p);
    let b = lazy_mod_mul(pp_y_plus_x, y_plus_x, p);
    
    // C = T1*2dt - lazy: 1 mul (both inputs assumed reduced)
    let c = lazy_mod_mul(pp.3.clone(), two_dt, p);
    
    // D = 2*Z1 - lazy: 1 mul (Z1 < p, constant 2 < p)
    let two = &T::one() + &T::one();
    let d_val = lazy_mod_mul(two, &pp.2, p);
    
    // E = B-A, F = D-C, G = D+C, H = B+A - all lazy: cheap add/sub operations
    let e = lazy_mod_sub(b.clone(), &a, p);
    let f = lazy_mod_sub(d_val.clone(), &c, p); 
    let g = lazy_mod_add(d_val, &c, p);
    let h = lazy_mod_add(b, &a, p);
    
    // Final coordinates: X3 = E*F, Y3 = G*H, Z3 = F*G, T3 = E*H - lazy: 4 muls only
    let x3 = lazy_mod_mul(e.clone(), &f, p);
    let y3 = lazy_mod_mul(g.clone(), &h, p);
    let z3 = lazy_mod_mul(f, &g, p);
    let t3 = lazy_mod_mul(e, &h, p);
    
    (x3, y3, z3, t3)
}

// Original version kept for comparison/fallback
fn point_add_niels<T: BrigIntStrict>(pp: &Point<T>, niels: &NielsPoint<T>, p: &T) -> Point<T>
where
    for<'a> &'a T: core::ops::BitAnd<Output = T>
        + core::ops::Rem<&'a T, Output = T>
        + core::ops::Add<&'a T, Output = T>
        + core::ops::Sub<T, Output = T>
        + core::ops::Sub<&'a T, Output = T>
        + core::ops::Mul<&'a T, Output = T>
        + core::ops::Div<&'a T, Output = T>,
{
    // Mixed Edwards addition formula from "Twisted Edwards Curves" paper
    // Input: P = (X1:Y1:Z1:T1) in extended, Q = (y+x, y-x, 2dt) in Niels
    // Output: P+Q in extended coordinates
    
    let (y_plus_x, y_minus_x, two_dt) = niels;
    
    // A = (Y1-X1)*(y-x)  
    let pp_y_minus_x = strict_mod_sub(pp.1.clone(), &pp.0, p);
    let a = strict_mod_mul(pp_y_minus_x, y_minus_x, p);
    
    // B = (Y1+X1)*(y+x)
    let pp_y_plus_x = strict_mod_add(pp.1.clone(), &pp.0, p);
    let b = strict_mod_mul(pp_y_plus_x, y_plus_x, p);
    
    // C = T1*2dt
    let c = strict_mod_mul(pp.3.clone(), two_dt, p);
    
    // D = 2*Z1
    let two = &T::one() + &T::one();
    let d_val = strict_mod_mul(two, &pp.2, p);
    
    // E = B-A, F = D-C, G = D+C, H = B+A
    let e = strict_mod_sub(b.clone(), &a, p);
    let f = strict_mod_sub(d_val.clone(), &c, p); 
    let g = strict_mod_add(d_val, &c, p);
    let h = strict_mod_add(b, &a, p);
    
    // X3 = E*F, Y3 = G*H, Z3 = F*G, T3 = E*H
    let x3 = strict_mod_mul(e.clone(), &f, p);
    let y3 = strict_mod_mul(g.clone(), &h, p);
    let z3 = strict_mod_mul(f, &g, p);
    let t3 = strict_mod_mul(e, &h, p);
    
    (x3, y3, z3, t3)
}

fn point_mul<T: BrigIntStrict>(s: T, pp: &Point<T>, p: &T, d: &T) -> Point<T>
where
    for<'a> &'a T: core::ops::BitAnd<Output = T>
        + core::ops::Rem<&'a T, Output = T>
        + core::ops::Add<&'a T, Output = T>
        + core::ops::Sub<T, Output = T>
        + core::ops::Sub<&'a T, Output = T>
        + core::ops::Mul<&'a T, Output = T>
        + core::ops::Div<&'a T, Output = T>,
{
    let mut q = (T::zero(), T::one(), T::one(), T::zero());
    let mut current = (
        &pp.0 + &T::zero(),
        &pp.1 + &T::zero(),
        &pp.2 + &T::zero(),
        &pp.3 + &T::zero(),
    );
    let mut remaining = s;

    while remaining > T::zero() {
        let remaining_copy = &remaining + &T::zero();
        if remaining_copy & T::one() == T::one() {
            // q = point_add(&q, &current, p, d)
            q = point_add(&q, &current, p, d);
        }
        // current = point_add(&current, &current, p, d) (point doubling)
        current = point_add(&current, &current, p, d);
        remaining >>= 1;
    }
    q
}

// JSF-based double scalar multiplication: s*G + h*A using Joint Sparse Form
// Reduces point additions by ~40-50% compared to binary methods - no lookup tables needed!
// Uses Niels coordinates for precomputed points to save ~2M per addition
fn jsf_double_scalar_mul<T: BrigIntStrict>(
    s: T,        // scalar 1
    g: &Point<T>, // base point G  
    h: T,        // scalar 2
    a: &Point<T>, // public key point A
    p: &T,       // prime modulus
    d: &T        // curve parameter d
) -> Point<T>
where
    for<'a> &'a T: core::ops::BitAnd<Output = T>
        + core::ops::Rem<&'a T, Output = T>
        + core::ops::Add<&'a T, Output = T>
        + core::ops::Sub<T, Output = T>
        + core::ops::Sub<&'a T, Output = T>
        + core::ops::Mul<&'a T, Output = T>
        + core::ops::Div<&'a T, Output = T>,
{
    // Generate JSF representation for both scalars
    let jsf = crate::jsf::JsfIterator::new(s, h);
    
    // Identity point in extended coordinates
    let mut result = (T::zero(), T::one(), T::one(), T::zero());
    
    // Convert base points to Niels form for faster additions
    let g_niels = to_niels_lazy(g, p, d);
    let a_niels = to_niels_lazy(a, p, d);
    
    // Create negative Niels points: (Y+X, Y-X, 2dT) -> (Y-X, Y+X, -2dT) 
    let neg_g_niels = (
        g_niels.1.clone(),                       // Y-X (swapped)
        g_niels.0.clone(),                       // Y+X (swapped)
        lazy_mod_sub(T::zero(), &g_niels.2, p) // -2dT LAZY: 1 sub vs 2 divisions
    );
    
    let neg_a_niels = (
        a_niels.1.clone(),                       // Y-X (swapped)  
        a_niels.0.clone(),                       // Y+X (swapped)
        lazy_mod_sub(T::zero(), &a_niels.2, p) // -2dT LAZY: 1 sub vs 2 divisions
    );
    
    // Process JSF digits from MSB to LSB
    for digit in jsf.digits_msb_first() {
        // Always double the result (use dedicated doubling for efficiency)
        result = point_double_lazy(&result, p);
        
        // Add ±G based on s digit using mixed Niels addition
        match digit.s_digit {
            1 => result = point_add_niels_lazy(&result, &g_niels, p),
            -1 => result = point_add_niels_lazy(&result, &neg_g_niels, p),
            0 => {}, // No addition needed
            _ => unreachable!("JSF digits must be -1, 0, or 1"),
        }
        
        // Add ±A based on h digit using mixed Niels addition
        match digit.h_digit {
            1 => result = point_add_niels_lazy(&result, &a_niels, p),
            -1 => result = point_add_niels_lazy(&result, &neg_a_niels, p),
            0 => {}, // No addition needed
            _ => unreachable!("JSF digits must be -1, 0, or 1"),
        }
    }
    
    result
}

// Optimized JSF double scalar multiplication using byte-based processing
// Avoids expensive bigint operations by working directly on 32-byte scalars
fn jsf_double_scalar_mul_bytes<T: BrigIntStrict>(
    s_bytes: &[u8; 32], // scalar 1 as bytes
    g: &Point<T>,       // base point G  
    h_bytes: &[u8; 32], // scalar 2 as bytes
    a: &Point<T>,       // public key point A
    p: &T,              // prime modulus
    d: &T               // curve parameter d
) -> Point<T>
where
    for<'a> &'a T: core::ops::BitAnd<Output = T>
        + core::ops::Rem<&'a T, Output = T>
        + core::ops::Add<&'a T, Output = T>
        + core::ops::Sub<T, Output = T>
        + core::ops::Sub<&'a T, Output = T>
        + core::ops::Mul<&'a T, Output = T>
        + core::ops::Div<&'a T, Output = T>,
{
    // Generate JSF representation using optimized byte processing
    let jsf = crate::jsf::JsfIterator::from_bytes_32(s_bytes, h_bytes);
    
    // Identity point in extended coordinates
    let mut result = (T::zero(), T::one(), T::one(), T::zero());
    
    // Convert base points to Niels form for faster additions
    let g_niels = to_niels_lazy(g, p, d);
    let a_niels = to_niels_lazy(a, p, d);
    
    // Create negative Niels points: (Y+X, Y-X, 2dT) -> (Y-X, Y+X, -2dT) 
    let neg_g_niels = (
        g_niels.1.clone(),                       // Y-X (swapped)
        g_niels.0.clone(),                       // Y+X (swapped)
        lazy_mod_sub(T::zero(), &g_niels.2, p) // -2dT LAZY: 1 sub vs 2 divisions
    );
    
    let neg_a_niels = (
        a_niels.1.clone(),                       // Y-X (swapped)  
        a_niels.0.clone(),                       // Y+X (swapped)
        lazy_mod_sub(T::zero(), &a_niels.2, p) // -2dT LAZY: 1 sub vs 2 divisions
    );
    
    // Process JSF digits from MSB to LSB
    for digit in jsf.digits_msb_first() {
        // Always double the result (use dedicated doubling for efficiency)
        result = point_double_lazy(&result, p);
        
        // Add ±G based on s digit using mixed Niels addition
        match digit.s_digit {
            1 => result = point_add_niels_lazy(&result, &g_niels, p),
            -1 => result = point_add_niels_lazy(&result, &neg_g_niels, p),
            0 => {}, // No addition needed
            _ => unreachable!("JSF digits must be -1, 0, or 1"),
        }
        
        // Add ±A based on h digit using mixed Niels addition
        match digit.h_digit {
            1 => result = point_add_niels_lazy(&result, &a_niels, p),
            -1 => result = point_add_niels_lazy(&result, &neg_a_niels, p),
            0 => {}, // No addition needed
            _ => unreachable!("JSF digits must be -1, 0, or 1"),
        }
    }
    
    result
}

// LAZY Point negation: assumes input coordinates < p, result < p
// Eliminates 2 expensive divisions to 2 fast subtractions
fn point_negate_lazy<T: BrigIntStrict>(pp: &Point<T>, p: &T) -> Point<T>
where
    for<'a> &'a T: core::ops::Add<&'a T, Output = T>
        + core::ops::Sub<&'a T, Output = T>,
{
    // In Edwards coordinates, negating a point (x,y) gives (-x,y)
    // In extended coordinates (X:Y:Z:T), this becomes (-X:Y:Z:-T)
    let neg_x = lazy_mod_sub(T::zero(), &pp.0, p);  // LAZY: 1 sub vs 2 divisions
    let neg_t = lazy_mod_sub(T::zero(), &pp.3, p);  // LAZY: 1 sub vs 2 divisions
    (neg_x, pp.1.clone(), pp.2.clone(), neg_t)
}

fn point_negate<T: BrigIntStrict>(pp: &Point<T>, p: &T) -> Point<T>
where
    for<'a> &'a T: core::ops::BitAnd<Output = T>
        + core::ops::Rem<&'a T, Output = T>
        + core::ops::Add<&'a T, Output = T>
        + core::ops::Sub<T, Output = T>
        + core::ops::Sub<&'a T, Output = T>
        + core::ops::Mul<&'a T, Output = T>
        + core::ops::Div<&'a T, Output = T>,
{
    // In Edwards coordinates, negating a point (x,y) gives (-x,y)
    // In extended coordinates (X:Y:Z:T), this becomes (-X:Y:Z:-T)
    let neg_x = strict_mod_sub(T::zero(), &pp.0, p);
    let neg_t = strict_mod_sub(T::zero(), &pp.3, p);
    (neg_x, pp.1.clone(), pp.2.clone(), neg_t)
}

// LAZY Point equality: assumes input coordinates < p
// Eliminates ~12 expensive divisions to ~6 divisions + fast comparisons
fn point_equal_lazy<T: BrigIntStrict>(pp: &Point<T>, qq: &Point<T>, p: &T) -> bool
where
    for<'a> &'a T: core::ops::Add<&'a T, Output = T>
        + core::ops::Sub<&'a T, Output = T>
        + core::ops::Mul<&'a T, Output = T>
        + core::ops::Rem<&'a T, Output = T>,
{
    // term1 = pp.0 * qq.2 mod p - LAZY: single reduction on result
    let term1 = lazy_mod_mul(pp.0.clone(), &qq.2, p);

    // term2 = qq.0 * pp.2 mod p - LAZY: single reduction on result  
    let term2 = lazy_mod_mul(qq.0.clone(), &pp.2, p);

    // term3 = pp.1 * qq.2 mod p - LAZY: single reduction on result
    let term3 = lazy_mod_mul(pp.1.clone(), &qq.2, p);

    // term4 = qq.1 * pp.2 mod p - LAZY: single reduction on result
    let term4 = lazy_mod_mul(qq.1.clone(), &pp.2, p);

    // Check if term1 - term2 == 0 (mod p) and term3 - term4 == 0 (mod p) - LAZY: fast subs
    let diff1 = lazy_mod_sub(term1, &term2, p);
    let diff2 = lazy_mod_sub(term3, &term4, p);

    diff1 == T::zero() && diff2 == T::zero()
}

fn point_equal<T: BrigIntStrict>(pp: &Point<T>, qq: &Point<T>, p: &T) -> bool
where
    for<'a> &'a T: core::ops::BitAnd<Output = T>
        + core::ops::Rem<&'a T, Output = T>
        + core::ops::Add<&'a T, Output = T>
        + core::ops::Sub<T, Output = T>
        + core::ops::Sub<&'a T, Output = T>
        + core::ops::Mul<&'a T, Output = T>
        + core::ops::Div<&'a T, Output = T>,
{
    // term1 = pp.0 * qq.2 mod p
    let term1 = strict_mod_mul(&pp.0 + &T::zero(), &qq.2, p);

    // term2 = qq.0 * pp.2 mod p
    let term2 = strict_mod_mul(&qq.0 + &T::zero(), &pp.2, p);

    // term3 = pp.1 * qq.2 mod p
    let term3 = strict_mod_mul(&pp.1 + &T::zero(), &qq.2, p);

    // term4 = qq.1 * pp.2 mod p
    let term4 = strict_mod_mul(&qq.1 + &T::zero(), &pp.2, p);

    // Check if term1 - term2 == 0 (mod p) and term3 - term4 == 0 (mod p)
    let diff1 = strict_mod_sub(term1, &term2, p);
    let diff2 = strict_mod_sub(term3, &term4, p);

    if diff1 != T::zero() {
        false
    } else if diff2 != T::zero() {
        false
    } else {
        true
    }
}

pub fn verify<T: BrigIntStrict>(public: [u8; 32], msg: &[u8], signature: [u8; 64]) -> bool
where
    for<'a> &'a T: core::ops::BitAnd<Output = T>
        + core::ops::Rem<&'a T, Output = T>
        + core::ops::Add<&'a T, Output = T>
        + core::ops::Sub<T, Output = T>
        + core::ops::Sub<&'a T, Output = T>
        + core::ops::Mul<&'a T, Output = T>
        + core::ops::Div<&'a T, Output = T>,
{
    let total_start = std::time::Instant::now();

    let p = T::from_bytes_le(&P_BYTES);
    let d = T::from_bytes_le(&D_BYTES);
    let q = T::from_bytes_le(&Q_BYTES);

    let g = (
        T::from_bytes_le(&G_X_BYTES),
        T::from_bytes_le(&G_Y_BYTES),
        T::one(),
        T::from_bytes_le(&G_T_BYTES),
    );

    let start = std::time::Instant::now();
    let aa = decompress_edward_point(public, &p, &d);
    info!(
        "TIMING: decompress_edward_point(public) took {:.3}ms",
        start.elapsed().as_secs_f64() * 1000.0
    );
    if aa.is_none() {
        return false;
    }
    let aa = aa.unwrap();
    let rrs: [u8; 32] = signature[0..32]
        .try_into()
        .expect("Invalid signature length");

    let start = std::time::Instant::now();
    let rr = decompress_edward_point(rrs, &p, &d);
    info!(
        "TIMING: decompress_edward_point(rrs) took {:.3}ms",
        start.elapsed().as_secs_f64() * 1000.0
    );
    if rr.is_none() {
        return false;
    }
    let rr = rr.unwrap();

    let s_bytes: [u8; 32] = signature[32..64]
        .try_into()
        .expect("invalid signature length");

    let s = T::from_bytes_le(&s_bytes);
    if &s >= &q {
        return false;
    }
    let rrs = rrs.as_slice();
    let public = public.as_slice();
    let mut storage = [0u8; 128];

    let concat = concat_emul(&[rrs, public, msg], &mut storage);
    let start = std::time::Instant::now();
    let h = sha512_modq(&concat, &q);
    info!(
        "TIMING: sha512_modq took {:.3}ms",
        start.elapsed().as_secs_f64() * 1000.0
    );

    // Use JSF (Joint Sparse Form): compute s*G + h*(-A) and compare with R
    // JSF reduces point additions by ~40-50% compared to binary methods
    let neg_aa = point_negate_lazy(&aa, &p);
    let start = std::time::Instant::now();
    let sbb_minus_haa = jsf_double_scalar_mul(s, &g, h, &neg_aa, &p, &d);
    info!(
        "TIMING: jsf_double_scalar_mul(s*G - h*A) took {:.3}ms",
        start.elapsed().as_secs_f64() * 1000.0
    );

    let start = std::time::Instant::now();
    let result = point_equal_lazy(&sbb_minus_haa, &rr, &p);
    info!(
        "TIMING: point_equal took {:.3}ms",
        start.elapsed().as_secs_f64() * 1000.0
    );

    info!(
        "TIMING: TOTAL verify() took {:.3}ms",
        total_start.elapsed().as_secs_f64() * 1000.0
    );
    result
}
