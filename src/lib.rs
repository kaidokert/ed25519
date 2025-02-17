#![cfg_attr(not(feature = "std"), no_std)]

extern crate lazy_static;
extern crate sha2;

mod num_bigint;

#[cfg(feature = "std")]
use log::info;

#[cfg(feature = "defmt")]
use defmt::info;

pub mod ed25519 {
    use super::info;

    pub type Point = (BigInt, BigInt, BigInt, BigInt);

    use super::num_bigint;
    use num_bigint::BigInt;

    use lazy_static::lazy_static;

    use sha2::{Digest, Sha512};

    lazy_static! {
        pub static ref P: BigInt = BigInt::from_str_radix(
            "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed",
            16
        )
        .expect("Worked");
        pub static ref D: BigInt = BigInt::from_str_radix(
            "52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3",
            16
        )
        .expect("Worked");
        pub static ref G_Y: BigInt = BigInt::from_str_radix(
            "6666666666666666666666666666666666666666666666666666666666666658",
            16
        )
        .expect("Worked");
        pub static ref G_X: BigInt = BigInt::from_str_radix(
            "216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a",
            16
        )
        .expect("Worked");
        pub static ref G: Point = (
            G_X.clone(),
            G_Y.clone(),
            BigInt::from(1),
            BigInt::from_str_radix(
                "67875f0fd78b766566ea4e8e64abe37d20f09f80775152f56dde8ab3a5b7dda3",
                16
            )
            .expect("Worked")
        );
        pub static ref Q: BigInt = BigInt::from_str_radix(
            "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed",
            16
        )
        .expect("Worked");
    }

    // We are going to get a slice of slices, and we want to concatenate them into a single slice.
    pub fn concat_emul<'a>(slices: &[&[u8]], storage: &'a mut [u8]) -> &'a [u8] {
        let total_len = slices.iter().map(|s| s.len()).sum();
        let mut offset = 0;
        for slice in slices {
            storage[offset..offset + slice.len()].copy_from_slice(slice);
            offset += slice.len();
        }
        &storage[..total_len]
    }

    pub fn decode_little_endian(b: &[u8]) -> BigInt {
        BigInt::from_bytes_le(num_bigint::Sign::Plus, &b[0..32])
    }

    pub fn modp_inv(m: &BigInt, p: &BigInt) -> BigInt {
        m.modpow(&(p - BigInt::from(2)), p)
    }

    pub fn recover_x(y: &BigInt, sign: u8, p: &BigInt, d: &BigInt) -> Option<BigInt> {
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
            let weird = ((&x).bit(0) as u8) != sign;

            if weird {
                x = p - &x;
            }

            Some(x)
        }
    }

    pub fn decompress_edward_point(
        k: [u8; 32],
        p: &BigInt,
        d: &BigInt,
    ) -> Option<Point> {
        let mut k_list = k.clone();

        let sign = k_list[k.len() - 1] >> 7;
        k_list[k.len() - 1] &= 0b01111111;

        let y = decode_little_endian(&k_list);

        if &y > p {
            None
        } else {
            let x = recover_x(&y, sign, p, d);
            x.map(|x| (x.clone(), y.clone(), BigInt::from(1), (x * y) % p))
        }
    }

    pub fn point_equal(pp: &Point, qq: &Point, p: &BigInt) -> bool {
        let term1 = &pp.0 * &qq.2;
        let term2 = &qq.0 * &pp.2;

        let term3 = &pp.1 * &qq.2;
        let term4 = &qq.1 * &pp.2;
        if (term1.mod_sub(&term2, p)) % p != BigInt::from(0) {
            false
        } else if (term3.mod_sub(&term4, p)) % p != BigInt::from(0) {
            false
        } else {
            true
        }
    }

    pub fn point_add(pp: &Point, qq: &Point, p: &BigInt, d: &BigInt) -> Point {
        // Instead of creating new BigInts for these intermediates, we can chain the operations
        let a = pp.1.mod_sub(&pp.0, p).mod_mul(&qq.1.mod_sub(&qq.0, p), p);
        let b = pp.1.mod_add(&pp.0, p).mod_mul(&qq.1.mod_add(&qq.0, p), p);

        // Avoid intermediate allocations by chaining
        let c = BigInt::from(2)
            .mod_mul(&pp.3, p)
            .mod_mul(&qq.3, p)
            .mod_mul(d, p);

        let d_val = BigInt::from(2).mod_mul(&pp.2, p).mod_mul(&qq.2, p);

        // e, f, g, h could be computed inline where used instead of stored
        let x3 = b.mod_sub(&a, p).mod_mul(&d_val.mod_sub(&c, p), p);
        let y3 = (d_val + &c).mod_mul(&(&b + &a), p);
        let z3 = d_val.mod_sub(&c, p).mod_mul(&(d_val + &c), p);
        let t3 = b.mod_sub(&a, p).mod_mul(&(&b + &a), p);

        (x3, y3, z3, t3)
    }

    pub fn point_mul(s: BigInt, pp: &Point, p: &BigInt, d: &BigInt) -> Point {
        let mut q = (
            BigInt::from(0),
            BigInt::from(1),
            BigInt::from(1),
            BigInt::from(0),
        );
        let mut current = pp.clone();
        let mut remaining = s;

        while remaining > BigInt::from(0) {
            if remaining.bit(0) {
                q = point_add(&q, &current, p, d);
            }
            current = point_add(&current, &current, p, d);
            remaining >>= 1;
        }
        q
    }

    pub fn sha512_modq(msg: &[u8], q: &BigInt) -> BigInt {
        let finalized = Sha512::new().chain_update(msg).finalize();
        let hash = finalized.as_slice();

        let result_nomodq = BigInt::from_bytes_le(num_bigint::Sign::Plus, &hash[0..64]);
        result_nomodq % q
    }

    pub fn verify(public: [u8; 32], msg: &[u8], signature: [u8; 64]) -> bool {
        let p = &*P;
        let d = &*D;
        let q = &*Q;

        info!("Decompressing public key");
        let aa = decompress_edward_point(public, p, d);

        if aa.is_none() {
            return false;
        }

        let aa = aa.unwrap();

        let rrs: [u8; 32] = signature[0..32]
            .try_into()
            .expect("Invalid signature length");

        info!("Decompressing rrs");
        let rr = decompress_edward_point(rrs, p, d);
        if rr.is_none() {
            return false;
        }

        let rr = rr.unwrap();

        let s_bytes: [u8; 32] = signature[32..64]
            .try_into()
            .expect("invalid signature length");
        let s = decode_little_endian(&s_bytes);

        if &s >= q {
            return false;
        }

        let rrs = rrs.as_slice();
        let public = public.as_slice();
        let mut storage = [0u8; 128];
        let concat = concat_emul(&[rrs, public, msg], &mut storage);
        info!("Doing sha512_modq");
        let h = sha512_modq(&concat, q);

        info!("Doing point_mul(s, G)");
        let sbb = point_mul(s, &*G, p, d);
        info!("Doing point_mul(h, aa)");
        let haa = point_mul(h, &aa, p, d);
        info!("Doing point_add(rr, haa)");
        let second_point = point_add(&rr, &haa, p, d);
        info!("Doing point_equal(sbb, second_point, &p)");
        point_equal(&sbb, &second_point, p)
    }
}
