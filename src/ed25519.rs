use crate::num_bigint::BigInt;
use num_traits::Zero;

/// Ed25519 curve point in extended coordinates (X, Y, Z, T).
pub type Point = (BigInt, BigInt, BigInt, BigInt);

/// Field prime: P = 2^255 - 19.
pub fn p() -> BigInt {
    BigInt::from(2i32).pow(255) - BigInt::from(19i32)
}

/// Modular inverse: a^(p-2) mod p (Fermat's little theorem).
fn modp_inv(a: &BigInt, p: &BigInt) -> BigInt {
    let exp = *p - BigInt::from(2i32);
    a.modpow(&exp, p)
}

/// Curve parameter D = -121665/121666 mod P.
///
/// Computed as (P - 121665) * 121666^(P-2) mod P since our BigInt is unsigned.
pub fn d() -> BigInt {
    let p = p();
    let num = p - BigInt::from(121665i32);
    let den_inv = modp_inv(&BigInt::from(121666i32), &p);
    (num * den_inv).rem_euclid(&p)
}

/// Group order: Q = 2^252 + 27742317777372353535851937790883648493.
pub fn q() -> BigInt {
    let base = BigInt::from(2i32).pow(252);
    let offset = BigInt::from_str_radix("27742317777372353535851937790883648493", 10)
        .expect("valid decimal literal");
    base + offset
}

/// L is an alias for the group order Q.
pub fn l() -> BigInt {
    q()
}

/// Generator Y coordinate: G_Y = 4/5 mod P.
pub fn g_y() -> BigInt {
    let p = p();
    let four = BigInt::from(4i32);
    let five_inv = modp_inv(&BigInt::from(5i32), &p);
    (four * five_inv).rem_euclid(&p)
}

/// sqrt(-1) mod P, i.e. I = 2^((P-1)/4) mod P.
pub fn sqrt_m1() -> BigInt {
    let p = p();
    let exp = (p - BigInt::from(1i32)).div_euclid(&BigInt::from(4i32));
    BigInt::from(2i32).modpow(&exp, &p)
}

/// Recover the X coordinate from a Y coordinate and a sign bit.
///
/// Returns `None` if no valid X exists for the given Y on the curve.
pub fn recover_x(y: &BigInt, sign: u8) -> Option<BigInt> {
    let prime = p();
    let d_val = d();

    // x^2 = (y^2 - 1) / (d * y^2 + 1)  mod p
    let y2 = (*y * *y).rem_euclid(&prime);
    let num = (y2 - BigInt::from(1i32)).rem_euclid(&prime);
    let den = (d_val * y2 + BigInt::from(1i32)).rem_euclid(&prime);
    let den_inv = modp_inv(&den, &prime);
    let x2 = (num * den_inv).rem_euclid(&prime);

    if x2 == BigInt::from(0i32) {
        return if sign > 0 {
            None
        } else {
            Some(BigInt::from(0i32))
        };
    }

    // x = x2^((p+3)/8) mod p
    let exp = (prime + BigInt::from(3i32)).div_euclid(&BigInt::from(8i32));
    let mut x = x2.modpow(&exp, &prime);

    // If x^2 != x2 mod p, multiply by sqrt(-1)
    if (x * x - x2).rem_euclid(&prime) != BigInt::from(0i32) {
        let i = sqrt_m1();
        x = (x * i).rem_euclid(&prime);
    }

    // Verify the square root is correct
    if (x * x - x2).rem_euclid(&prime) != BigInt::from(0i32) {
        return None;
    }

    // Adjust sign
    if (x.bit(0) as u8) != sign {
        x = prime - x;
    }

    Some(x)
}

/// Base point B in extended coordinates (X, Y, Z, T).
pub fn base_point() -> Point {
    let gy = g_y();
    let gx = recover_x(&gy, 0).expect("base point X must exist");
    let p = p();
    let t = (gx * gy).rem_euclid(&p);
    (gx, gy, BigInt::from(1i32), t)
}

/// Neutral point (identity) in extended coordinates.
pub fn neutral_point() -> Point {
    (
        BigInt::from(0i32),
        BigInt::from(1i32),
        BigInt::from(1i32),
        BigInt::from(0i32),
    )
}

/// Add two extended Edwards points.
pub fn point_add(pp: &Point, qq: &Point) -> Point {
    let p = p();
    let d_val = d();
    let (x1, y1, z1, t1) = pp;
    let (x2, y2, z2, t2) = qq;

    let a = y1.mod_sub(x1, &p).mod_mul(&y2.mod_sub(x2, &p), &p);
    let b = y1.mod_add(x1, &p).mod_mul(&y2.mod_add(x2, &p), &p);
    let two = BigInt::from(2i32);
    let c = two.mod_mul(t1, &p).mod_mul(t2, &p).mod_mul(&d_val, &p);
    let d_term = two.mod_mul(z1, &p).mod_mul(z2, &p);

    let e = b.mod_sub(&a, &p);
    let f = d_term.mod_sub(&c, &p);
    let g = d_term.mod_add(&c, &p);
    let h = b.mod_add(&a, &p);

    let x3 = e.mod_mul(&f, &p);
    let y3 = g.mod_mul(&h, &p);
    let z3 = f.mod_mul(&g, &p);
    let t3 = e.mod_mul(&h, &p);

    (x3, y3, z3, t3)
}

/// Scalar multiplication via double-and-add.
pub fn point_mul(s: BigInt, pp: &Point) -> Point {
    if s.is_zero() {
        return neutral_point();
    }

    let mut acc = neutral_point();
    let bit_len = s.bits();
    for bit_index in (0..bit_len).rev() {
        acc = point_add(&acc, &acc);
        if s.bit(bit_index as u64) {
            acc = point_add(&acc, pp);
        }
    }
    acc
}

/// Compare two projective points for equality.
pub fn point_equal(pp: &Point, qq: &Point) -> bool {
    let p = p();
    let (x1, y1, z1, _) = pp;
    let (x2, y2, z2, _) = qq;
    let x_left = x1.mod_mul(z2, &p);
    let x_right = x2.mod_mul(z1, &p);
    if x_left != x_right {
        return false;
    }
    let y_left = y1.mod_mul(z2, &p);
    let y_right = y2.mod_mul(z1, &p);
    y_left == y_right
}

#[cfg(test)]
mod tests {
    use super::*;

    fn point_from_compressed(bytes: [u8; 32]) -> Result<Point, String> {
        let mut y_bytes = bytes;
        let sign = y_bytes[31] >> 7;
        y_bytes[31] &= 0b0111_1111;
        let y = BigInt::from_bytes_le(&y_bytes);
        let x = recover_x(&y, sign).ok_or_else(|| {
            format!(
                "recover_x failed for compressed point y={:?}, sign={}",
                y, sign
            )
        })?;
        let p = p();
        let t = (x * y).rem_euclid(&p);
        Ok((x, y, BigInt::from(1i32), t))
    }

    #[test]
    fn p_has_255_bits() {
        assert_eq!(p().bits(), 255);
    }

    #[test]
    fn q_has_253_bits() {
        assert_eq!(q().bits(), 253);
    }

    #[test]
    fn l_equals_q() {
        assert_eq!(l(), q());
    }

    #[test]
    fn p_mod_4_is_1() {
        let p = p();
        let rem = p.rem_euclid(&BigInt::from(4i32));
        assert_eq!(rem, BigInt::from(1i32));
    }

    #[test]
    fn sqrt_m1_squared_is_neg1() {
        let p = p();
        let i = sqrt_m1();
        // i^2 mod p should equal p - 1 (which is -1 mod p)
        let i_sq = (i * i).rem_euclid(&p);
        assert_eq!(i_sq, p - BigInt::from(1i32));
    }

    #[test]
    fn d_matches_known_value() {
        // D mod P is a well-known constant; verify via byte representation.
        let d = d();
        let p = p();
        // D must be in range [0, P)
        assert!(d < p);
        assert!(d > BigInt::from(0i32));
        // D = -121665/121666 mod P, verify: D * 121666 + 121665 ≡ 0 (mod P)
        let check = (d * BigInt::from(121666i32) + BigInt::from(121665i32)).rem_euclid(&p);
        assert_eq!(check, BigInt::from(0i32));
    }

    #[test]
    fn g_y_is_4_over_5() {
        let p = p();
        let gy = g_y();
        // gy * 5 mod p == 4
        let check = (gy * BigInt::from(5i32)).rem_euclid(&p);
        assert_eq!(check, BigInt::from(4i32));
    }

    #[test]
    fn base_point_is_on_curve() {
        let p = p();
        let d = d();
        let (bx, by, bz, bt) = base_point();

        // Verify Z == 1 and T == X*Y for the base point
        assert_eq!(bz, BigInt::from(1i32));
        assert_eq!(bt, (bx * by).rem_euclid(&p));

        // Ed25519 curve equation: -x^2 + y^2 = 1 + d*x^2*y^2 (mod p)
        let x2 = (bx * bx).rem_euclid(&p);
        let y2 = (by * by).rem_euclid(&p);

        // lhs = -x^2 + y^2 = p - x^2 + y^2 mod p
        let lhs = (p - x2 + y2).rem_euclid(&p);

        // rhs = 1 + d*x^2*y^2 mod p
        let dx2y2 = (d * x2 % p * y2).rem_euclid(&p);
        let rhs = (BigInt::from(1i32) + dx2y2).rem_euclid(&p);

        assert_eq!(lhs, rhs);
    }

    #[test]
    fn base_point_matches_known_coordinates() {
        let (bx, by, _, _) = base_point();

        // Known X coordinate of Ed25519 base point
        let expected_x = BigInt::from_str_radix(
            "15112221349535400772501151409588531511454012693041857206046113283949847762202",
            10,
        )
        .unwrap();
        // Known Y coordinate: 4/5 mod P
        let expected_y = BigInt::from_str_radix(
            "46316835694926478169428394003475163141307993866256225615783033603165251855960",
            10,
        )
        .unwrap();

        assert_eq!(bx, expected_x);
        assert_eq!(by, expected_y);
    }

    #[test]
    fn recover_x_returns_none_for_invalid_sign_at_zero() {
        // When x2 == 0, sign must be 0; otherwise None
        // y=1 gives x^2 = (1-1)/(d+1) = 0, so x=0
        let result = recover_x(&BigInt::from(1i32), 1);
        assert!(result.is_none());
    }

    #[test]
    fn recover_x_returns_zero_for_y_one() {
        let result = recover_x(&BigInt::from(1i32), 0);
        assert_eq!(result, Some(BigInt::from(0i32)));
    }

    #[test]
    fn point_mul_zero_is_neutral() {
        let base = base_point();
        let result = point_mul(BigInt::from(0i32), &base);
        assert!(point_equal(&result, &neutral_point()));
    }

    #[test]
    fn point_mul_one_is_base() {
        let base = base_point();
        let result = point_mul(BigInt::from(1i32), &base);
        assert!(point_equal(&result, &base_point()));
    }

    #[test]
    fn point_add_matches_scalar_addition() {
        let n = BigInt::from(3i32);
        let m = BigInt::from(5i32);
        let base = base_point();
        let left = point_add(&point_mul(n, &base), &point_mul(m, &base));
        let right = point_mul(BigInt::from(8i32), &base);
        assert!(point_equal(&left, &right));
    }

    #[test]
    fn point_add_associativity_spot_check() {
        let base = base_point();
        let a = point_mul(BigInt::from(2i32), &base);
        let b = point_mul(BigInt::from(3i32), &base);
        let c = point_mul(BigInt::from(4i32), &base);

        let left = point_add(&point_add(&a, &b), &c);
        let right = point_add(&a, &point_add(&b, &c));

        assert!(point_equal(&left, &right));
    }

    #[test]
    fn point_equal_reflexive_and_distinct() {
        let base = base_point();
        assert!(point_equal(&base, &base));
        let other = point_mul(BigInt::from(2i32), &base);
        assert!(!point_equal(&base, &other));
    }

    #[test]
    fn small_scalar_mul_known_values() {
        let base = base_point();
        let two_b = point_mul(BigInt::from(2i32), &base);
        let three_b = point_mul(BigInt::from(3i32), &base);

        let expected_two = point_from_compressed([
            0xc9, 0xa3, 0xf8, 0x6a, 0xae, 0x46, 0x5f, 0x0e, 0x56, 0x51, 0x38, 0x64, 0x51, 0x0f,
            0x39, 0x97, 0x56, 0x1f, 0xa2, 0xc9, 0xe8, 0x5e, 0xa2, 0x1d, 0xc2, 0x29, 0x23, 0x09,
            0xf3, 0xcd, 0x60, 0x22,
        ])
        .unwrap();
        let expected_three = point_from_compressed([
            0xd4, 0xb4, 0xf5, 0x78, 0x48, 0x68, 0xc3, 0x02, 0x04, 0x03, 0x24, 0x67, 0x17, 0xec,
            0x16, 0x9f, 0xf7, 0x9e, 0x26, 0x60, 0x8e, 0xa1, 0x26, 0xa1, 0xab, 0x69, 0xee, 0x77,
            0xd1, 0xb1, 0x67, 0x12,
        ])
        .unwrap();

        assert!(point_equal(&two_b, &expected_two));
        assert!(point_equal(&three_b, &expected_three));
    }
}
