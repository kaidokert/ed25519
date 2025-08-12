use modmath::{constrained_mod_add, constrained_mod_exp, constrained_mod_inv, constrained_mod_mul, constrained_mod_sub};

#[cfg(feature = "montgomery")]
use modmath::constrained_montgomery_mod_exp;

#[cfg(feature = "std")]
use log::info;

#[cfg(feature = "defmt")]
use defmt::info;


use crate::{BrigIntConstrained, CoreIntConstrained, Point};
use crate::{P_BYTES, D_BYTES, Q_BYTES, G_X_BYTES, G_Y_BYTES, G_T_BYTES};

fn print_value<T: BrigIntConstrained>(label: &str, value: &T)
where
    for<'a> &'a T: core::ops::Rem<&'a T, Output = T>
        + core::ops::BitAnd<Output = T>,
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

fn recover_x<T: BrigIntConstrained>(y: T, sign: u8, p: &T, d: T) -> Option<T>
where
    for<'a> &'a T: core::ops::Rem<&'a T, Output = T>
        + core::ops::BitAnd<Output = T>,
{
    let one = T::one();

    // First compute y² mod p
    let y2 = y.clone();
    let y2 = constrained_mod_mul(y, &y2, p);

    // Create another copy of y² for later use
    let y2_copy = y2.clone();

    // left = (y² - 1) mod p
    let left = constrained_mod_sub(y2, &one, p);

    // denom_raw = (d * y²) mod p
    let denom_raw = constrained_mod_mul(d, &y2_copy, p);

    // denom = (denom_raw + 1) mod p
    let denom = constrained_mod_add(denom_raw, &one, p);

    // inv_denom = denom^(-1) mod p
    let two = one.clone() + one.clone();
    let three = two.clone() + one.clone();
    let exp = p.clone() - two.clone();

    info!("recovering x");
    print_value("denom", &denom);
    print_value("exp", &exp);
    print_value("p", &p);

    let inv_denom = {
        // Montgomery not supported for constrained mode due to complex trait bounds
        constrained_mod_exp(denom, &exp, p)
    };

    // Finally, x2 = left * inv_denom mod p
    let x2 = constrained_mod_mul(left, &inv_denom, p);

    if x2 == T::zero() {
        if sign > 0 { None } else { Some(T::zero()) }
    } else {
        // three already defined above
        let p3 = p.clone() + three;
        let four = two.clone() + two.clone();
        let eight = four.clone() + four.clone();

        let exp = p3 / &eight;
        let x2_copy = x2.clone();

        let mut x = {
            // Montgomery not supported for constrained mode due to complex trait bounds
            constrained_mod_exp(x2, &exp, p)
        };

        let exp = (p.clone() - one.clone()) / &four;
        let modp_sqrt_m1 = {
            // Montgomery not supported for constrained mode due to complex trait bounds
            constrained_mod_exp(two.clone(), &exp, p)
        };

        let x_copy = x.clone();
        let x_for_mul = x.clone();
        let tmp1 = constrained_mod_mul(x_for_mul, &x_copy, p);
        let tmp2 = constrained_mod_sub(tmp1, &x2_copy, p);
        if tmp2 != T::zero() {
            x = constrained_mod_mul(x, &modp_sqrt_m1, p);
        }

        let x_copy2 = x.clone();
        let x_for_final_check = x.clone();
        let tmp1 = constrained_mod_mul(x_for_final_check, &x_copy2, p);
        let x2_copy2 = x2_copy.clone();
        let tmp2 = constrained_mod_sub(tmp1, &x2_copy2, p);
        if tmp2 != T::zero() {
            return None;
        }
        let x_for_check = x.clone();
        let weird = (&x_for_check & &one.clone() == one) as u8 != sign;
        // To be continued...
        if weird {
            x = p.clone() - x;
        }

        Some(x)
    }
}

fn decompress_edward_point<T: BrigIntConstrained>(k: [u8; 32], p: &T, d: &T) -> Option<Point<T>>
where
    for<'a> &'a T: core::ops::Rem<&'a T, Output = T>
        + core::ops::BitAnd<Output = T>,
{
    let mut k_list = k.clone();
    let sign = k_list[k.len() - 1] >> 7;
    k_list[k.len() - 1] &= 0b01111111;
    let y = T::from_bytes_le(&k_list[0..32]);

    if &y > p {
        None
    } else {
        let d_owned = d.clone();
        let y_owned = y.clone();
        let x = recover_x(y, sign, p, d_owned);
        x.map(|x_val| {
            let x_copy = x_val.clone();
            let y_copy = y_owned.clone();
            (x_val, y_owned, T::one(), constrained_mod_mul(x_copy, &y_copy, p))
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

fn sha512_modq<T: BrigIntConstrained>(msg: &[u8], q: &T) -> T
where
    for<'a> &'a T: core::ops::Rem<&'a T, Output = T>
        + core::ops::BitAnd<Output = T>,
{
    let mut compact_sha = hmac_sha512::Hash::new();
    compact_sha.update(msg);
    let finalized = compact_sha.finalize();
    let hash = finalized.as_slice();

    let result_nomodq = T::from_bytes_le(&hash[0..64]);
    result_nomodq % q
}

fn point_add<T: BrigIntConstrained>(pp: &Point<T>, qq: &Point<T>, p: &T, d: &T) -> Point<T>
where
    for<'a> &'a T: core::ops::Rem<&'a T, Output = T>
        + core::ops::BitAnd<Output = T>,
{
    // a = (pp.1 - pp.0) * (qq.1 - qq.0) mod p
    let pp1_sub_pp0 = constrained_mod_sub(pp.1.clone(), &pp.0, p);
    let qq1_sub_qq0 = constrained_mod_sub(qq.1.clone(), &qq.0, p);
    let a = constrained_mod_mul(pp1_sub_pp0, &qq1_sub_qq0, p);

    // b = (pp.1 + pp.0) * (qq.1 + qq.0) mod p
    let pp1_add_pp0 = constrained_mod_add(pp.1.clone(), &pp.0, p);
    let qq1_add_qq0 = constrained_mod_add(qq.1.clone(), &qq.0, p);
    let b = constrained_mod_mul(pp1_add_pp0, &qq1_add_qq0, p);

    // c = 2 * pp.3 * qq.3 * d mod p
    let two = T::one() + T::one();
    let pp3_mul_qq3 = constrained_mod_mul(pp.3.clone(), &qq.3, p);
    let c_temp = constrained_mod_mul(two.clone(), &pp3_mul_qq3, p);
    let c = constrained_mod_mul(c_temp, d, p);

    // d_val = 2 * pp.2 * qq.2 mod p
    let two2 = T::one() + T::one();
    let pp2_mul_qq2 = constrained_mod_mul(pp.2.clone(), &qq.2, p);
    let d_val = constrained_mod_mul(two2, &pp2_mul_qq2, p);

    // Create all needed copies upfront
    let b_copy1 = b.clone();
    let d_val_copy1 = d_val.clone();
    let a_copy = a.clone();
    let c_copy1 = c.clone();

    // x3 = (b - a) * (d_val - c) mod p
    let b_sub_a = constrained_mod_sub(b.clone(), &a, p);
    let d_sub_c = constrained_mod_sub(d_val.clone(), &c, p);
    let x3 = constrained_mod_mul(b_sub_a.clone(), &d_sub_c, p);

    // y3 = (d_val + c) * (b + a) mod p
    let d_add_c = constrained_mod_add(d_val_copy1, &c_copy1, p);
    let b_add_a = constrained_mod_add(b_copy1, &a_copy, p);
    let y3 = constrained_mod_mul(d_add_c.clone(), &b_add_a, p);

    // z3 = (d_val - c) * (d_val + c) mod p
    let z3 = constrained_mod_mul(d_sub_c.clone(), &d_add_c, p);

    // t3 = (b - a) * (b + a) mod p
    let t3 = constrained_mod_mul(b_sub_a, &b_add_a, p);

    (x3, y3, z3, t3)
}

fn point_mul<T: BrigIntConstrained>(s: T, pp: &Point<T>, p: &T, d: &T) -> Point<T>
where
    for<'a> &'a T: core::ops::Rem<&'a T, Output = T>
        + core::ops::BitAnd<Output = T>,
{
    let mut q = (T::zero(), T::one(), T::one(), T::zero());
    let mut current = (
        pp.0.clone(),
        pp.1.clone(),
        pp.2.clone(),
        pp.3.clone(),
    );
    let mut remaining = s;

    while remaining > T::zero() {
        let remaining_copy = remaining.clone();
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

fn point_equal<T: BrigIntConstrained>(pp: &Point<T>, qq: &Point<T>, p: &T) -> bool
where
    for<'a> &'a T: core::ops::Rem<&'a T, Output = T>
        + core::ops::BitAnd<Output = T>,
{
    // term1 = pp.0 * qq.2 mod p
    let term1 = constrained_mod_mul(pp.0.clone(), &qq.2, p);

    // term2 = qq.0 * pp.2 mod p
    let term2 = constrained_mod_mul(qq.0.clone(), &pp.2, p);

    // term3 = pp.1 * qq.2 mod p
    let term3 = constrained_mod_mul(pp.1.clone(), &qq.2, p);

    // term4 = qq.1 * pp.2 mod p
    let term4 = constrained_mod_mul(qq.1.clone(), &pp.2, p);

    // Check if term1 - term2 == 0 (mod p) and term3 - term4 == 0 (mod p)
    let diff1 = constrained_mod_sub(term1, &term2, p);
    let diff2 = constrained_mod_sub(term3, &term4, p);

    if diff1 != T::zero() {
        false
    } else if diff2 != T::zero() {
        false
    } else {
        true
    }
}

pub fn verify<T: BrigIntConstrained>(public: [u8; 32], msg: &[u8], signature: [u8; 64]) -> bool
where
    for<'a> &'a T: core::ops::Rem<&'a T, Output = T>
        + core::ops::BitAnd<Output = T>,
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

    let start = std::time::Instant::now();
    let sbb = point_mul(s, &g, &p, &d);
    info!(
        "TIMING: point_mul(s, g) took {:.3}ms",
        start.elapsed().as_secs_f64() * 1000.0
    );

    let start = std::time::Instant::now();
    let haa = point_mul(h, &aa, &p, &d);
    info!(
        "TIMING: point_mul(h, aa) took {:.3}ms",
        start.elapsed().as_secs_f64() * 1000.0
    );

    let start = std::time::Instant::now();
    let second_point = point_add(&rr, &haa, &p, &d);
    info!(
        "TIMING: point_add(rr, haa) took {:.3}ms",
        start.elapsed().as_secs_f64() * 1000.0
    );

    let start = std::time::Instant::now();
    let result = point_equal(&sbb, &second_point, &p);
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