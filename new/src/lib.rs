use modmath::{basic_mod_add, basic_mod_inv, basic_mod_mul, basic_mod_sub};

use modmath::{
    basic_compute_montgomery_params, basic_compute_montgomery_params_with_method,
    basic_from_montgomery, basic_montgomery_mod_exp, basic_montgomery_mod_mul,
    basic_montgomery_mul, basic_to_montgomery,
};

use modmath::{
    strict_mod_add, strict_mod_exp, strict_mod_inv, strict_mod_mul, strict_mod_sub,
    strict_montgomery_mod_exp,
};

#[cfg(feature = "std")]
use log::info;

#[cfg(feature = "defmt")]
use defmt::info;

const USE_MONTGOMERY: bool = false;

pub trait CoreInt:
    Sized
    + core::cmp::PartialOrd
    + num_traits::One
    + num_traits::Zero
    + num_traits::ops::overflowing::OverflowingAdd
    + num_traits::ops::overflowing::OverflowingSub
    + core::ops::Shr<usize, Output = Self>
    + core::ops::Shl<usize, Output = Self>
    + core::ops::Add<Output = Self>
    + core::ops::Sub<Output = Self>
    + core::ops::BitAnd<Output = Self>
    + core::ops::ShrAssign<usize>
    + for<'a> core::ops::RemAssign<&'a Self>
    + for<'a> core::ops::DivAssign<&'a Self>
    + for<'a> core::ops::Rem<&'a Self, Output = Self>
    + for<'a> core::ops::Div<&'a Self, Output = Self>
    + for<'a> core::ops::Mul<&'a Self, Output = Self>
    + for<'a> core::ops::Add<&'a Self, Output = Self>
    + for<'a> core::ops::Sub<&'a Self, Output = Self>
    + for<'a> core::ops::AddAssign<&'a Self>
where
    for<'a> &'a Self: core::ops::BitAnd<Output = Self>
        + core::ops::Rem<&'a Self, Output = Self>
        + core::ops::Add<&'a Self, Output = Self>
        + core::ops::Mul<&'a Self, Output = Self>
        + core::ops::Div<&'a Self, Output = Self>
        + core::ops::Sub<Self, Output = Self>,
{
}
impl<T> CoreInt for T
where
    T: Sized
        + core::cmp::PartialOrd
        + num_traits::One
        + num_traits::Zero
        + num_traits::ops::overflowing::OverflowingAdd
        + num_traits::ops::overflowing::OverflowingSub
        + core::ops::Shr<usize, Output = T>
        + core::ops::Shl<usize, Output = T>
        + core::ops::Add<Output = T>
        + core::ops::Sub<Output = T>
        + core::ops::BitAnd<Output = T>
        + core::ops::ShrAssign<usize>
        + for<'a> core::ops::RemAssign<&'a T>
        + for<'a> core::ops::DivAssign<&'a T>
        + for<'a> core::ops::Rem<&'a T, Output = T>
        + for<'a> core::ops::Div<&'a T, Output = T>
        + for<'a> core::ops::Mul<&'a T, Output = T>
        + for<'a> core::ops::Add<&'a T, Output = T>
        + for<'a> core::ops::Sub<&'a T, Output = T>
        + for<'a> core::ops::AddAssign<&'a T>,
    for<'a> &'a T: core::ops::BitAnd<Output = T>
        + core::ops::Rem<&'a T, Output = T>
        + core::ops::Add<&'a T, Output = T>
        + core::ops::Mul<&'a T, Output = T>
        + core::ops::Div<&'a T, Output = T>
        + core::ops::Sub<T, Output = T>,
{
}

type Point<T: CoreInt> = (T, T, T, T);

pub trait BrigInt: CoreInt
where
    for<'a> &'a Self: core::ops::BitAnd<Output = Self>
        + core::ops::Rem<&'a Self, Output = Self>
        + core::ops::Add<&'a Self, Output = Self>
        + core::ops::Mul<&'a Self, Output = Self>
        + core::ops::Div<&'a Self, Output = Self>
        + core::ops::Sub<Self, Output = Self>,
{
    fn from_bytes_le(bytes: &[u8]) -> Self;
}

#[cfg(feature = "fixed-bigint")]
impl BrigInt for fixed_bigint::FixedUInt<u32, 16> {
    fn from_bytes_le(bytes: &[u8]) -> Self {
        fixed_bigint::FixedUInt::from_le_bytes(bytes)
    }
}

const P_BYTES: [u8; 32] = [
    237, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127,
];
const D_BYTES: [u8; 32] = [
    163, 120, 89, 19, 202, 77, 235, 117, 171, 216, 65, 65, 77, 10, 112, 0, 152, 232, 121, 119, 121,
    64, 199, 140, 115, 254, 111, 43, 238, 108, 3, 82,
];
const Q_BYTES: [u8; 32] = [
    237, 211, 245, 92, 26, 99, 18, 88, 214, 156, 247, 162, 222, 249, 222, 20, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 16,
];

const G_X_BYTES: [u8; 32] = [
    26, 213, 37, 143, 96, 45, 86, 201, 178, 167, 37, 149, 96, 199, 44, 105, 92, 220, 214, 253, 49,
    226, 164, 192, 254, 83, 110, 205, 211, 54, 105, 33,
];
const G_Y_BYTES: [u8; 32] = [
    88, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102,
    102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102,
];
const G_T_BYTES: [u8; 32] = [
    163, 221, 183, 165, 179, 138, 222, 109, 245, 82, 81, 119, 128, 159, 240, 32, 125, 227, 171,
    100, 142, 78, 234, 102, 101, 118, 139, 215, 15, 95, 135, 103,
];

fn recover_x<T: BrigInt>(y: T, sign: u8, p: &T, d: T) -> Option<T>
where
    for<'a> &'a T: core::ops::BitAnd<Output = T>
        + core::ops::Rem<&'a T, Output = T>
        + core::ops::Add<&'a T, Output = T>
        + core::ops::Sub<&'a T, Output = T>
        + core::ops::Mul<&'a T, Output = T>
        + core::ops::Div<&'a T, Output = T>
        + core::ops::Sub<T, Output = T>,
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
    let exp = p - &two;
    let inv_denom = if USE_MONTGOMERY && true {
        strict_montgomery_mod_exp(denom, &exp, p).unwrap()
    } else {
        strict_mod_exp(denom, &exp, p)
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
        let mut x = if USE_MONTGOMERY && false {
            strict_montgomery_mod_exp(x2, &exp, p).unwrap()
        } else {
            strict_mod_exp(x2, &exp, p)
        };

        let exp = (p - &one) / &four;
        let modp_sqrt_m1 = if USE_MONTGOMERY && false {
            strict_montgomery_mod_exp(two, &exp, p).unwrap()
        } else {
            strict_mod_exp(two, &exp, p)
        };

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
        let weird = (&x_for_check & &one == one) as u8 != sign;
        // To be continued...
        if weird {
            x = p - &x;
        }

        Some(x)
    }
}

fn decompress_edward_point<T: BrigInt>(k: [u8; 32], p: &T, d: &T) -> Option<Point<T>>
where
    for<'a> &'a T: core::ops::BitAnd<Output = T>
        + core::ops::Rem<&'a T, Output = T>
        + core::ops::Add<&'a T, Output = T>
        + core::ops::Sub<&'a T, Output = T>
        + core::ops::Mul<&'a T, Output = T>
        + core::ops::Div<&'a T, Output = T>
        + core::ops::Sub<T, Output = T>,
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
        let x = recover_x(y, sign, p, d_owned);
        x.map(|x_val| {
            let x_copy = &x_val + &T::zero();
            let y_copy = &y_owned + &T::zero();
            (x_val, y_owned, T::one(), strict_mod_mul(x_copy, &y_copy, p))
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

fn sha512_modq<T: BrigInt>(msg: &[u8], q: &T) -> T
where
    for<'a> &'a T: core::ops::BitAnd<Output = T>
        + core::ops::Rem<&'a T, Output = T>
        + core::ops::Add<&'a T, Output = T>
        + core::ops::Sub<&'a T, Output = T>
        + core::ops::Mul<&'a T, Output = T>
        + core::ops::Div<&'a T, Output = T>
        + core::ops::Sub<T, Output = T>,
{
    let mut compact_sha = hmac_sha512::Hash::new();
    compact_sha.update(msg);
    let finalized = compact_sha.finalize();
    let hash = finalized.as_slice();

    let result_nomodq = T::from_bytes_le(&hash[0..64]);
    result_nomodq % q
}

fn point_add<T: BrigInt>(pp: &Point<T>, qq: &Point<T>, p: &T, d: &T) -> Point<T>
where
    for<'a> &'a T: core::ops::BitAnd<Output = T>
        + core::ops::Rem<&'a T, Output = T>
        + core::ops::Add<&'a T, Output = T>
        + core::ops::Sub<&'a T, Output = T>
        + core::ops::Mul<&'a T, Output = T>
        + core::ops::Div<&'a T, Output = T>
        + core::ops::Sub<T, Output = T>,
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
    let b_copy2 = &b + &T::zero();
    let d_val_copy1 = &d_val + &T::zero();
    let d_val_copy2 = &d_val + &T::zero();
    let a_copy = &a + &T::zero();
    let c_copy1 = &c + &T::zero();
    let c_copy2 = &c + &T::zero();

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

fn point_mul<T: BrigInt>(s: T, pp: &Point<T>, p: &T, d: &T) -> Point<T>
where
    for<'a> &'a T: core::ops::BitAnd<Output = T>
        + core::ops::Rem<&'a T, Output = T>
        + core::ops::Add<&'a T, Output = T>
        + core::ops::Sub<&'a T, Output = T>
        + core::ops::Mul<&'a T, Output = T>
        + core::ops::Div<&'a T, Output = T>
        + core::ops::Sub<T, Output = T>,
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

fn point_equal<T: BrigInt>(pp: &Point<T>, qq: &Point<T>, p: &T) -> bool
where
    for<'a> &'a T: core::ops::BitAnd<Output = T>
        + core::ops::Rem<&'a T, Output = T>
        + core::ops::Add<&'a T, Output = T>
        + core::ops::Sub<&'a T, Output = T>
        + core::ops::Mul<&'a T, Output = T>
        + core::ops::Div<&'a T, Output = T>
        + core::ops::Sub<T, Output = T>,
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

pub fn verify<T: BrigInt>(public: [u8; 32], msg: &[u8], signature: [u8; 64]) -> bool
where
    for<'a> &'a T: core::ops::BitAnd<Output = T>
        + core::ops::Rem<&'a T, Output = T>
        + core::ops::Add<&'a T, Output = T>
        + core::ops::Sub<&'a T, Output = T>
        + core::ops::Mul<&'a T, Output = T>
        + core::ops::Div<&'a T, Output = T>
        + core::ops::Sub<T, Output = T>,
{
    let p = T::from_bytes_le(&P_BYTES);
    let d = T::from_bytes_le(&D_BYTES);
    let q = T::from_bytes_le(&Q_BYTES);

    let g = (
        T::from_bytes_le(&G_X_BYTES),
        T::from_bytes_le(&G_Y_BYTES),
        T::one(),
        T::from_bytes_le(&G_T_BYTES),
    );
    info!("Decompressing public key");
    let aa = decompress_edward_point(public, &p, &d);
    if aa.is_none() {
        return false;
    }
    let aa = aa.unwrap();
    let rrs: [u8; 32] = signature[0..32]
        .try_into()
        .expect("Invalid signature length");

    info!("Decompressing rrs");
    let rr = decompress_edward_point(rrs, &p, &d);
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
    info!("Doing sha512_modq");
    let h = sha512_modq(&concat, &q);

    let sbb = point_mul(s, &g, &p, &d);
    info!("Doing point_mul(h, aa)");
    let haa = point_mul(h, &aa, &p, &d);
    info!("Doing point_add(rr, haa)");
    let second_point = point_add(&rr, &haa, &p, &d);
    info!("Doing point_equal(sbb, second_point, &p)");
    point_equal(&sbb, &second_point, &p)
}
