#![cfg_attr(not(feature = "std"), no_std)]

mod num_bigint;

use hmac_sha512::Hash;

#[cfg(feature = "std")]
use log::info;

#[cfg(feature = "defmt")]
use defmt::info;

pub mod ed25519 {
    use super::info;

    pub type Point = (BigInt, BigInt, BigInt, BigInt);

    use super::num_bigint;
    use num_bigint::BigInt;

    const P_BYTES: [u8; 32] = [
        237, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127
    ];

    const D_BYTES: [u8; 32] = [
        163, 120, 89, 19, 202, 77, 235, 117, 171, 216, 65, 65, 77, 10, 112, 0,
        152, 232, 121, 119, 121, 64, 199, 140, 115, 254, 111, 43, 238, 108, 3, 82
    ];

    const G_Y_BYTES: [u8; 32] = [
        88, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102,
        102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102
    ];

    const G_X_BYTES: [u8; 32] = [
        26, 213, 37, 143, 96, 45, 86, 201, 178, 167, 37, 149, 96, 199, 44, 105,
        92, 220, 214, 253, 49, 226, 164, 192, 254, 83, 110, 205, 211, 54, 105, 33
    ];

    const G_T_BYTES: [u8; 32] = [
        163, 221, 183, 165, 179, 138, 222, 109, 245, 82, 81, 119, 128, 159, 240, 32,
        125, 227, 171, 100, 142, 78, 234, 102, 101, 118, 139, 215, 15, 95, 135, 103
    ];

    const Q_BYTES: [u8; 32] = [
        237, 211, 245, 92, 26, 99, 18, 88, 214, 156, 247, 162, 222, 249, 222, 20,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16
    ];

    fn concat_emul<'a>(slices: &[&[u8]], storage: &'a mut [u8]) -> &'a [u8] {
        let total_len = slices.iter().map(|s| s.len()).sum();
        let mut offset = 0;
        for slice in slices {
            storage[offset..offset + slice.len()].copy_from_slice(slice);
            offset += slice.len();
        }
        &storage[..total_len]
    }

    fn decode_little_endian(b: &[u8]) -> BigInt {
        BigInt::from_bytes_le(&b[0..32])
    }

    fn modp_inv(m: &BigInt, p: &BigInt) -> BigInt {
        m.modpow(&(p - BigInt::from(2)), p)
    }

    fn recover_x(y: &BigInt, sign: u8, p: &BigInt, d: &BigInt) -> Option<BigInt> {
        // First compute y² mod p
        let y2 = y.mod_mul(y, p);

        // left = (y² - 1) mod p
        let left = y2.mod_sub(&BigInt::from(1), p);

        // denom_raw = (d * y²) mod p
        let denom_raw = d.mod_mul(&y2, p);

        // denom = (denom_raw + 1) mod p
        let denom = denom_raw.mod_add(&BigInt::from(1), p);

        // inv_denom = denom^(-1) mod p
        let inv_denom = modp_inv(&denom, p);

        // Finally, x2 = left * inv_denom mod p
        let x2 = left.mod_mul(&inv_denom, p);

        if x2 == BigInt::from(0) {
            if sign > 0 {
                None
            } else {
                Some(BigInt::from(0))
            }
        } else {
            let p3 = p + BigInt::from(3);
            let mut x = x2.modpow(&(p3 / &BigInt::from(8)), p);

            let modp_sqrt_m1 =
                BigInt::from(2).modpow(&((p - BigInt::from(1)) / &BigInt::from(4)), p);

            if x.mod_mul(&x, p).mod_sub(&x2, p) != BigInt::from(0) {
                x = x.mod_mul(&modp_sqrt_m1, p);
            }

            if x.mod_mul(&x, p).mod_sub(&x2, p) != BigInt::from(0) {
                return None;
            }
            let weird = ((&x).is_odd() as u8) != sign;

            if weird {
                x = p - &x;
            }

            Some(x)
        }
    }

    fn decompress_edward_point(k: [u8; 32], p: &BigInt, d: &BigInt) -> Option<Point> {
        let mut k_list = k.clone();

        let sign = k_list[k.len() - 1] >> 7;
        k_list[k.len() - 1] &= 0b01111111;

        let y = decode_little_endian(&k_list);

        if &y > p {
            None
        } else {
            let x = recover_x(&y, sign, p, d);
            x.map(|x| (x.clone(), y.clone(), BigInt::from(1), x.mod_mul(&y, p)))
        }
    }

    fn point_equal(pp: &Point, qq: &Point, p: &BigInt) -> bool {
        let term1 = &pp.0 * &qq.2;
        let term2 = &qq.0 * &pp.2;

        let term3 = &pp.1 * &qq.2;
        let term4 = &qq.1 * &pp.2;
        if term1.mod_sub(&term2, p) != BigInt::from(0) {
            false
        } else if term3.mod_sub(&term4, p) != BigInt::from(0) {
            false
        } else {
            true
        }
    }

    fn point_add(pp: &Point, qq: &Point, p: &BigInt, d: &BigInt) -> Point {
        let a = pp.1.mod_sub(&pp.0, p).mod_mul(&qq.1.mod_sub(&qq.0, p), p);
        let b = pp.1.mod_add(&pp.0, p).mod_mul(&qq.1.mod_add(&qq.0, p), p);

        let c = BigInt::from(2)
            .mod_mul(&pp.3, p)
            .mod_mul(&qq.3, p)
            .mod_mul(d, p);

        let d_val = BigInt::from(2).mod_mul(&pp.2, p).mod_mul(&qq.2, p);

        let x3 = b.mod_sub(&a, p).mod_mul(&d_val.mod_sub(&c, p), p);
        let y3 = (d_val + &c).mod_mul(&(&b + &a), p);
        let z3 = d_val.mod_sub(&c, p).mod_mul(&(d_val + &c), p);
        let t3 = b.mod_sub(&a, p).mod_mul(&(&b + &a), p);

        (x3, y3, z3, t3)
    }

    fn point_mul(s: BigInt, pp: &Point, p: &BigInt, d: &BigInt) -> Point {
        let mut q = (
            BigInt::from(0),
            BigInt::from(1),
            BigInt::from(1),
            BigInt::from(0),
        );
        let mut current = pp.clone();
        let mut remaining = s;

        while remaining > BigInt::from(0) {
            if remaining.is_odd() {
                q = point_add(&q, &current, p, d);
            }
            current = point_add(&current, &current, p, d);
            remaining >>= 1;
        }
        q
    }

    fn sha512_modq(msg: &[u8], q: &BigInt) -> BigInt {
        let mut compact_sha = super::Hash::new();
        compact_sha.update(msg);
        let finalized = compact_sha.finalize();
        let hash = finalized.as_slice();

        let result_nomodq = BigInt::from_bytes_le(&hash[0..64]);
        result_nomodq % q
    }

    pub fn verify(public: [u8; 32], msg: &[u8], signature: [u8; 64]) -> bool {
        let p = BigInt::from_bytes_le(&P_BYTES);
        let d = BigInt::from_bytes_le(&D_BYTES);
        let q = BigInt::from_bytes_le(&Q_BYTES);
        
        let g = (
            BigInt::from_bytes_le(&G_X_BYTES),
            BigInt::from_bytes_le(&G_Y_BYTES),
            BigInt::from(1),
            BigInt::from_bytes_le(&G_T_BYTES)
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
        let s = decode_little_endian(&s_bytes);

        if &s >= &q {
            return false;
        }

        let rrs = rrs.as_slice();
        let public = public.as_slice();
        let mut storage = [0u8; 128];
        let concat = concat_emul(&[rrs, public, msg], &mut storage);
        info!("Doing sha512_modq");
        let h = sha512_modq(&concat, &q);

        info!("Doing point_mul(s, G)");
        let sbb = point_mul(s, &g, &p, &d);
        info!("Doing point_mul(h, aa)");
        let haa = point_mul(h, &aa, &p, &d);
        info!("Doing point_add(rr, haa)");
        let second_point = point_add(&rr, &haa, &p, &d);
        info!("Doing point_equal(sbb, second_point, &p)");
        point_equal(&sbb, &second_point, &p)
    }
}
