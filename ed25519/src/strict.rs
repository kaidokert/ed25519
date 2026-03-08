use crate::lazy_field::{lazy_mod_add, lazy_mod_sub};

use crate::montgomery_ctx::MontgomeryCtx;

use crate::{Point, UnsignedModularInt};

// Niels coordinates: (Y+X, Y-X, 2dT) - optimized for point additions
// Reduces point addition from 10M to 8M multiplications
type NielsPoint<T> = (T, T, T);
use crate::{D_BYTES, G_T_BYTES, G_X_BYTES, G_Y_BYTES, MODP_SQRT_M1_BYTES, P_BYTES, Q_BYTES};

#[inline(never)]
fn sha512_modq<T: UnsignedModularInt>(parts: &[&[u8]], q: &T) -> T
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
    for part in parts {
        compact_sha.update(part);
    }
    let finalized = compact_sha.finalize();
    let hash = finalized.as_slice();

    // Bit-by-bit Horner reduction: processes the full 512-bit hash without
    // requiring T to hold all 64 bytes. Works for any T >= 253 bits (> q).
    // At each step acc < q, so 2*acc < 2q < 2^254, which fits in 256-bit T.
    let mut acc = T::zero();
    let one = T::one();
    // Process from most significant bit (byte 63, bit 7) to least (byte 0, bit 0)
    // Hash is little-endian: byte 63 is MSB
    for byte_idx in (0..64).rev() {
        for bit_idx in (0..8).rev() {
            // acc = 2*acc + bit, then reduce
            let (doubled, _overflow) = acc.overflowing_add(&acc);
            acc = doubled;
            if (hash[byte_idx] >> bit_idx) & 1 == 1 {
                let (added, _) = acc.overflowing_add(&one);
                acc = added;
            }
            // acc < 2q + 1 here, so at most two subtractions needed
            if &acc >= q {
                acc = &acc - q;
            }
            if &acc >= q {
                acc = &acc - q;
            }
        }
    }
    acc
}

// =========================================================================
// Montgomery-domain point operations
// =========================================================================
// All multiplications use wide-REDC Montgomery multiplication instead of
// (a * b) % p. Add/sub remain unchanged.
// All point coordinates are kept in Montgomery form throughout.

#[inline(never)]
fn recover_x_mont<T>(y: T, sign: u8, p: &T, d: T, ctx: &MontgomeryCtx<T>) -> Option<T>
where
    T: UnsignedModularInt
        + Copy
        + modmath::WideMul
        + modmath::CiosMontMul
        + num_traits::ops::overflowing::OverflowingAdd
        + num_traits::WrappingMul
        + num_traits::WrappingAdd
        + num_traits::WrappingSub,
    for<'a> &'a T: core::ops::BitAnd<Output = T>
        + core::ops::Rem<&'a T, Output = T>
        + core::ops::Add<&'a T, Output = T>
        + core::ops::Sub<T, Output = T>
        + core::ops::Sub<&'a T, Output = T>
        + core::ops::Mul<&'a T, Output = T>
        + core::ops::Div<&'a T, Output = T>,
{
    let one = T::one();

    // Phase 1: Compute x² = (y²-1) / (d*y²+1) — scope all intermediates
    let x2 = {
        let y_m = ctx.to_mont(y);
        let d_m = ctx.to_mont(d);
        let y2_m = ctx.mont_mul(&y_m, &y_m);
        let y2 = ctx.from_mont(y2_m);
        let left = lazy_mod_sub(y2, &one, p);
        let denom_raw = ctx.from_mont(ctx.mont_mul(&d_m, &y2_m));
        let denom = lazy_mod_add(denom_raw, &one, p);
        let inv_denom = ctx.mont_inv(denom);
        let left_m = ctx.to_mont(left);
        let inv_denom_m = ctx.to_mont(inv_denom);
        ctx.from_mont(ctx.mont_mul(&left_m, &inv_denom_m))
    }; // y_m, d_m, y2_m, y2, left, denom, inv_denom, etc. all dead

    if x2 == T::zero() {
        return if sign > 0 { None } else { Some(T::zero()) };
    }

    // Phase 2: Compute exponent (p+3)/8 — scope arithmetic temps
    let exp = {
        let two = one + one;
        let three = two + one;
        let p3 = p + &three;
        let four = two + two;
        let eight = four + four;
        p3 / &eight
    }; // two, three, four, eight, p3 all dead

    // Phase 3: Square root via Montgomery exponentiation
    let mut x = ctx.mont_exp(x2, exp);
    // exp is dead

    // Phase 4: Verification — x² == x2? If not, multiply by sqrt(-1)
    {
        let x_m = ctx.to_mont(x);
        let tmp1 = ctx.from_mont(ctx.mont_mul(&x_m, &x_m));
        let tmp2 = lazy_mod_sub(tmp1, &x2, p);
        if tmp2 != T::zero() {
            let sqrt_m1_m = ctx.to_mont(T::from_bytes_le(&MODP_SQRT_M1_BYTES));
            let x_m2 = ctx.to_mont(x);
            x = ctx.from_mont(ctx.mont_mul(&x_m2, &sqrt_m1_m));
        }
    } // x_m, tmp1, tmp2, sqrt_m1_m all dead

    // Phase 5: Final check — x² == x2?
    {
        let x_m = ctx.to_mont(x);
        let tmp1 = ctx.from_mont(ctx.mont_mul(&x_m, &x_m));
        let tmp2 = lazy_mod_sub(tmp1, &x2, p);
        if tmp2 != T::zero() {
            return None;
        }
    } // x_m, tmp1, tmp2 all dead

    if (x & one == one) as u8 != sign {
        x = p - x;
    }

    Some(x)
}

// decompress_edward_point_mont uses recover_x_mont for the sqrt but returns
// points in NORMAL form. The caller (verify_mont) converts to Montgomery form.
#[inline(never)]
fn decompress_edward_point_mont<T>(
    k: [u8; 32],
    p: &T,
    d: &T,
    ctx: &MontgomeryCtx<T>,
) -> Option<Point<T>>
where
    T: UnsignedModularInt
        + Copy
        + modmath::WideMul
        + modmath::CiosMontMul
        + num_traits::ops::overflowing::OverflowingAdd
        + num_traits::WrappingMul
        + num_traits::WrappingAdd
        + num_traits::WrappingSub,
    for<'a> &'a T: core::ops::BitAnd<Output = T>
        + core::ops::Rem<&'a T, Output = T>
        + core::ops::Add<&'a T, Output = T>
        + core::ops::Sub<T, Output = T>
        + core::ops::Sub<&'a T, Output = T>
        + core::ops::Mul<&'a T, Output = T>
        + core::ops::Div<&'a T, Output = T>,
{
    let mut k_list = k;
    let sign = k_list[k.len() - 1] >> 7;
    k_list[k.len() - 1] &= 0b01111111;
    let y = T::from_bytes_le(&k_list[0..32]);

    if &y > p {
        None
    } else {
        let d_owned = d + &T::zero();
        let y_owned = y + T::zero();
        let x = recover_x_mont(y, sign, p, d_owned, ctx);
        x.map(|x_val| {
            // Compute T = x*y using Montgomery mul, but return point in normal form
            let x_m = ctx.to_mont(x_val);
            let y_m = ctx.to_mont(y_owned);
            let t = ctx.from_mont(ctx.mont_mul(&x_m, &y_m));
            (x_val, y_owned, T::one(), t)
        })
    }
}

#[inline(never)]
fn point_double_mont<T>(pp: &Point<T>, p: &T, ctx: &MontgomeryCtx<T>) -> Point<T>
where
    T: UnsignedModularInt
        + Copy
        + modmath::WideMul
        + modmath::CiosMontMul
        + num_traits::ops::overflowing::OverflowingAdd
        + num_traits::WrappingMul
        + num_traits::WrappingAdd
        + num_traits::WrappingSub,
    for<'a> &'a T: core::ops::Add<&'a T, Output = T> + core::ops::Sub<&'a T, Output = T>,
{
    // A = X^2
    let a = ctx.mont_mul(&pp.0, &pp.0);
    // B = Y^2
    let b = ctx.mont_mul(&pp.1, &pp.1);
    // C = 2*Z^2
    let z_squared = ctx.mont_mul(&pp.2, &pp.2);
    let c = lazy_mod_add(z_squared, &z_squared, p);
    // D = -A (since a = -1 for Ed25519)
    let d_val = lazy_mod_sub(T::zero(), &a, p);
    // E = (X+Y)^2 - A - B
    let x_plus_y = lazy_mod_add(pp.0, &pp.1, p);
    let x_plus_y_squared = ctx.mont_mul(&x_plus_y, &x_plus_y);
    let e_temp = lazy_mod_sub(x_plus_y_squared, &a, p);
    let e = lazy_mod_sub(e_temp, &b, p);
    // G = D + B
    let g = lazy_mod_add(d_val, &b, p);
    // F = G - C
    let f = lazy_mod_sub(g, &c, p);
    // H = D - B
    let h = lazy_mod_sub(d_val, &b, p);
    // Final coordinates
    let x2 = ctx.mont_mul(&e, &f);
    let y2 = ctx.mont_mul(&g, &h);
    let z2 = ctx.mont_mul(&f, &g);
    let t2 = ctx.mont_mul(&e, &h);
    (x2, y2, z2, t2)
}

fn to_niels_mont<T>(pp: &Point<T>, p: &T, d: &T, ctx: &MontgomeryCtx<T>) -> NielsPoint<T>
where
    T: UnsignedModularInt
        + Copy
        + modmath::WideMul
        + modmath::CiosMontMul
        + num_traits::ops::overflowing::OverflowingAdd
        + num_traits::WrappingMul
        + num_traits::WrappingAdd
        + num_traits::WrappingSub,
    for<'a> &'a T: core::ops::Add<&'a T, Output = T> + core::ops::Sub<&'a T, Output = T>,
{
    let y_plus_x = lazy_mod_add(pp.1, &pp.0, p);
    let y_minus_x = lazy_mod_sub(pp.1, &pp.0, p);
    let d_m = ctx.to_mont(*d);
    let dt = ctx.mont_mul(&d_m, &pp.3);
    let two_dt = lazy_mod_add(dt, &dt, p);
    (y_plus_x, y_minus_x, two_dt)
}

#[inline(never)]
fn point_add_niels_mont<T>(
    pp: &Point<T>,
    niels: &NielsPoint<T>,
    p: &T,
    ctx: &MontgomeryCtx<T>,
) -> Point<T>
where
    T: UnsignedModularInt
        + Copy
        + modmath::WideMul
        + modmath::CiosMontMul
        + num_traits::ops::overflowing::OverflowingAdd
        + num_traits::WrappingMul
        + num_traits::WrappingAdd
        + num_traits::WrappingSub,
    for<'a> &'a T: core::ops::Add<&'a T, Output = T> + core::ops::Sub<&'a T, Output = T>,
{
    let (y_plus_x, y_minus_x, two_dt) = niels;
    // A = (Y1-X1)*(y-x)
    let pp_y_minus_x = lazy_mod_sub(pp.1, &pp.0, p);
    let a = ctx.mont_mul(&pp_y_minus_x, y_minus_x);
    // B = (Y1+X1)*(y+x)
    let pp_y_plus_x = lazy_mod_add(pp.1, &pp.0, p);
    let b = ctx.mont_mul(&pp_y_plus_x, y_plus_x);
    // C = T1*2dt
    let c = ctx.mont_mul(&pp.3, two_dt);
    // D = 2*Z1
    let d_val = lazy_mod_add(pp.2, &pp.2, p);
    // E = B-A, F = D-C, G = D+C, H = B+A
    let e = lazy_mod_sub(b, &a, p);
    let f = lazy_mod_sub(d_val, &c, p);
    let g = lazy_mod_add(d_val, &c, p);
    let h = lazy_mod_add(b, &a, p);
    // Final coordinates
    let x3 = ctx.mont_mul(&e, &f);
    let y3 = ctx.mont_mul(&g, &h);
    let z3 = ctx.mont_mul(&f, &g);
    let t3 = ctx.mont_mul(&e, &h);
    (x3, y3, z3, t3)
}

#[inline(never)]
fn point_equal_mont<T>(pp: &Point<T>, qq: &Point<T>, p: &T, ctx: &MontgomeryCtx<T>) -> bool
where
    T: UnsignedModularInt
        + Copy
        + modmath::WideMul
        + modmath::CiosMontMul
        + num_traits::ops::overflowing::OverflowingAdd
        + num_traits::WrappingMul
        + num_traits::WrappingAdd
        + num_traits::WrappingSub,
    for<'a> &'a T: core::ops::Add<&'a T, Output = T> + core::ops::Sub<&'a T, Output = T>,
{
    let term1 = ctx.mont_mul(&pp.0, &qq.2);
    let term2 = ctx.mont_mul(&qq.0, &pp.2);
    let term3 = ctx.mont_mul(&pp.1, &qq.2);
    let term4 = ctx.mont_mul(&qq.1, &pp.2);
    let diff1 = lazy_mod_sub(term1, &term2, p);
    let diff2 = lazy_mod_sub(term3, &term4, p);
    diff1 == T::zero() && diff2 == T::zero()
}

#[inline(never)]
fn jsf_double_scalar_mul_mont<T>(
    s: T,
    g: &Point<T>,
    h: T,
    a: &Point<T>,
    p: &T,
    d: &T,
    ctx: &MontgomeryCtx<T>,
) -> Point<T>
where
    T: UnsignedModularInt
        + Copy
        + modmath::WideMul
        + modmath::CiosMontMul
        + num_traits::ops::overflowing::OverflowingAdd
        + num_traits::WrappingMul
        + num_traits::WrappingAdd
        + num_traits::WrappingSub,
    for<'a> &'a T: core::ops::BitAnd<Output = T>
        + core::ops::Rem<&'a T, Output = T>
        + core::ops::Add<&'a T, Output = T>
        + core::ops::Sub<T, Output = T>
        + core::ops::Sub<&'a T, Output = T>
        + core::ops::Mul<&'a T, Output = T>
        + core::ops::Div<&'a T, Output = T>,
{
    // Scope s, h — consumed by JsfIterator::new, dead after this
    let jsf = { crate::jsf::JsfIterator::new(s, h) };

    // Scope zero_m, one_m — only needed for identity point construction
    let mut result = {
        let zero_m = ctx.to_mont(T::zero());
        let one_m = ctx.to_mont(T::one());
        (zero_m, one_m, one_m, zero_m)
    };

    // Convert base points to Niels form (uses Montgomery mul internally)
    let g_niels = to_niels_mont(g, p, d, ctx);
    let a_niels = to_niels_mont(a, p, d, ctx);

    for digit in jsf.digits_msb_first() {
        result = point_double_mont(&result, p, ctx);
        // Compute negative Niels on-the-fly: (Y+X, Y-X, 2dT) -> (Y-X, Y+X, -2dT)
        // Avoids storing two 96B neg_niels points for entire loop
        match digit.s_digit {
            1 => result = point_add_niels_mont(&result, &g_niels, p, ctx),
            -1 => {
                let neg = (g_niels.1, g_niels.0, lazy_mod_sub(T::zero(), &g_niels.2, p));
                result = point_add_niels_mont(&result, &neg, p, ctx);
            }
            0 => {}
            _ => unreachable!("JSF digits must be -1, 0, or 1"),
        }
        match digit.h_digit {
            1 => result = point_add_niels_mont(&result, &a_niels, p, ctx),
            -1 => {
                let neg = (a_niels.1, a_niels.0, lazy_mod_sub(T::zero(), &a_niels.2, p));
                result = point_add_niels_mont(&result, &neg, p, ctx);
            }
            0 => {}
            _ => unreachable!("JSF digits must be -1, 0, or 1"),
        }
    }

    result
}

pub fn verify<T>(public: [u8; 32], msg: &[u8], signature: [u8; 64]) -> bool
where
    T: UnsignedModularInt
        + Copy
        + modmath::WideMul
        + modmath::CiosMontMul
        + num_traits::ops::overflowing::OverflowingAdd
        + num_traits::WrappingMul
        + num_traits::WrappingAdd
        + num_traits::WrappingSub,
    for<'a> &'a T: core::ops::BitAnd<Output = T>
        + core::ops::Rem<&'a T, Output = T>
        + core::ops::Add<&'a T, Output = T>
        + core::ops::Sub<T, Output = T>
        + core::ops::Sub<&'a T, Output = T>
        + core::ops::Mul<&'a T, Output = T>
        + core::ops::Div<&'a T, Output = T>,
{
    verify_mont::<T>(public, msg, signature)
}

#[inline(never)]
fn verify_mont<T>(public: [u8; 32], msg: &[u8], signature: [u8; 64]) -> bool
where
    T: UnsignedModularInt
        + Copy
        + modmath::WideMul
        + modmath::CiosMontMul
        + num_traits::ops::overflowing::OverflowingAdd
        + num_traits::WrappingMul
        + num_traits::WrappingAdd
        + num_traits::WrappingSub,
    for<'a> &'a T: core::ops::BitAnd<Output = T>
        + core::ops::Rem<&'a T, Output = T>
        + core::ops::Add<&'a T, Output = T>
        + core::ops::Sub<T, Output = T>
        + core::ops::Sub<&'a T, Output = T>
        + core::ops::Mul<&'a T, Output = T>
        + core::ops::Div<&'a T, Output = T>,
{
    let p = T::from_bytes_le(&P_BYTES);
    let d = T::from_bytes_le(&D_BYTES);

    // Precompute Montgomery context for field prime p
    let ctx = MontgomeryCtx::new(p);

    // Phase 1: Decompress public key -> neg_aa_mont (aa scoped to die here)
    let neg_aa_mont = {
        let aa = match decompress_edward_point_mont(public, &p, &d, &ctx) {
            Some(aa) => aa,
            None => return false,
        };
        let aa_m = (
            ctx.to_mont(aa.0),
            ctx.to_mont(aa.1),
            ctx.to_mont(aa.2),
            ctx.to_mont(aa.3),
        );
        (
            lazy_mod_sub(T::zero(), &aa_m.0, &p),
            aa_m.1,
            aa_m.2,
            lazy_mod_sub(T::zero(), &aa_m.3, &p),
        )
    }; // aa (128B) and aa_m (128B) are now dead

    let rrs: [u8; 32] = signature[0..32]
        .try_into()
        .expect("Invalid signature length");

    // Phase 2: Decompress R -> rr_mont (rr scoped to die here)
    let rr_mont = {
        let rr = match decompress_edward_point_mont(rrs, &p, &d, &ctx) {
            Some(rr) => rr,
            None => return false,
        };
        (
            ctx.to_mont(rr.0),
            ctx.to_mont(rr.1),
            ctx.to_mont(rr.2),
            ctx.to_mont(rr.3),
        )
    }; // rr (128B) is now dead

    let s_bytes: [u8; 32] = signature[32..64]
        .try_into()
        .expect("invalid signature length");
    let s = T::from_bytes_le(&s_bytes);

    // Phase 3: SHA-512 hash — scope q and storage so they die before JSF
    let h = {
        let q = T::from_bytes_le(&Q_BYTES);
        if s >= q {
            return false;
        }
        sha512_modq(&[rrs.as_slice(), public.as_slice(), msg], &q)
    }; // q (32B), storage (128B), rrs (32B) are now dead

    // Phase 4: Construct G in Montgomery form (normal-form scoped to die)
    let g_mont = {
        let g = (
            T::from_bytes_le(&G_X_BYTES),
            T::from_bytes_le(&G_Y_BYTES),
            T::one(),
            T::from_bytes_le(&G_T_BYTES),
        );
        (
            ctx.to_mont(g.0),
            ctx.to_mont(g.1),
            ctx.to_mont(g.2),
            ctx.to_mont(g.3),
        )
    }; // g normal-form (128B) is now dead

    // Phase 5: JSF double scalar multiplication
    let sbb_minus_haa = jsf_double_scalar_mul_mont(s, &g_mont, h, &neg_aa_mont, &p, &d, &ctx);

    // Phase 6: Final comparison
    point_equal_mont(&sbb_minus_haa, &rr_mont, &p, &ctx)
}
