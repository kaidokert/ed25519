#![cfg_attr(not(feature = "std"), no_std)]

extern crate lazy_static;
extern crate sha2;

mod num_bigint;

#[cfg(feature = "std")]
use log::{debug, error, info, warn};
#[cfg(feature = "std")]
use std::println;

#[cfg(feature = "defmt")]
use defmt::{debug, error, info, println, warn};

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

pub mod hex {

    use super::num_bigint;
    use num_bigint::BigInt;

    use lazy_static::lazy_static;

    lazy_static! {
        pub static ref P: BigInt = BigInt::from_str_radix(
            "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed",
            16
        )
        .expect("Worked");
        pub static ref A24: BigInt = BigInt::from_str_radix("1db42", 16).expect("Worked");
        pub static ref D: BigInt = BigInt::from_str_radix(
            "52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3",
            16
        )
        .expect("Worked");
    }

    // Extract the keys from the hex string
    pub fn decode(hexstr: &str) -> Result<BigInt, num_bigint::ParseBigIntError> {
        let r = BigInt::from_str_radix(hexstr, 16);
        r
    }

    pub fn hex64_to_vec32u8(hexstr: &str) -> [u8; 32] {
        assert!(hexstr.len() == 64, "Hexidacimal string size is wrong");
        let mut k_list: [u8; 32] = [0; 32];
        for i in 0..32 {
            k_list[i] = u8::from_str_radix(&hexstr[2 * i..2 * (i + 1)], 16)
                .expect("Error parsing hexidecimal string");
        }
        k_list
    }

    pub fn decode_little_endian(b: &[u8]) -> BigInt {
        BigInt::from_bytes_le(num_bigint::Sign::Plus, &b[0..32])
    }

    pub fn decode_scalar25519(k: &str) -> BigInt {
        let mut k_list: [u8; 32] = hex64_to_vec32u8(k);

        k_list[0] &= 248;
        k_list[31] &= 127;
        k_list[31] |= 64;

        decode_little_endian(k_list.as_slice())
    }

    pub fn decode_ucoordinate(k: &str) -> BigInt {
        let u_list: [u8; 32] = hex64_to_vec32u8(k);

        decode_little_endian(u_list.as_slice())
    }

    pub fn modp_inv(m: &BigInt, p: &BigInt) -> BigInt {
        m.modpow(&(p - BigInt::from(2)), p)
    }

    // Verified function.
    pub fn recover_x(y: &BigInt, sign: u8, p: BigInt, d: BigInt) -> Option<BigInt> {
        // First compute y² mod p
        let y2 = y.mod_mul(&y, &p);

        // left = (y² - 1) mod p
        let left = y2.mod_sub(&BigInt::from(1), &p);

        // denom_raw = (d * y²) mod p
        let denom_raw = d.mod_mul(&y2, &p);

        // denom = (denom_raw + 1) mod p
        let denom = denom_raw.mod_add(&BigInt::from(1), &p);

        // inv_denom = denom^(-1) mod p
        let inv_denom = modp_inv(&denom, &p);

        // Finally, x2 = left * inv_denom mod p
        let x2 = left.mod_mul(&inv_denom, &p);

        if x2 == 0.into() {
            if sign > 0 {
                None
            } else {
                Some(BigInt::from(0))
            }
        } else {
            let p3 = &p + BigInt::from(3);
            let mut x = x2.modpow(&(p3 / &BigInt::from(8)) , &p);
            
            let modp_sqrt_m1 =
                BigInt::from(2).modpow(&((&p - BigInt::from(1)) / &BigInt::from(4) ), &p);

            if x.mod_mul(&x, &p).mod_sub(&x2, &p) != BigInt::from(0) {
                x = x.mod_mul(&modp_sqrt_m1, &p);
            }

            if x.mod_mul(&x, &p).mod_sub(&x2, &p) != BigInt::from(0) {
                return None;
            }
            let weird = ((&x).bit(0) as u8) != sign;

            if weird {
                x = &p - &x;
            }

            Some(x)
        }
    }

    pub fn decompress_edward_point(
        k: [u8; 32],
        p: BigInt,
        d: BigInt,
    ) -> Option<(BigInt, BigInt, BigInt, BigInt)> {
        let mut k_list = k.clone();

        let sign = k_list[k.len() - 1] >> 7;
        k_list[k.len() - 1] &= 0b01111111;

        let y = decode_little_endian(&k_list);

        if &y > &p {
            return None;
        } else {
            let x = recover_x(&y, sign, p.clone(), d.clone());
            if x == None {
                return None;
            } else {
                let x = x.unwrap();
                return Some((x.clone(), y.clone(), BigInt::from(1), (x * y) % &p));
            }
        }
    }

    pub fn compress_edward_point(x: BigInt, y: BigInt, z: BigInt, p: BigInt) -> [u8; 32] {
        // No need to worry about t. Only provide x y and z.
        let zinv = modp_inv(&z, &p);
        let x = x.mod_mul(&zinv, &p);
        let y = y.mod_mul(&zinv, &p);

        //let x_bytes = x.to_le_bytes();
        let mut y_bytes = y.to_le_bytes();
        let length = y_bytes.len();

        y_bytes[length - 1] |= (x.bit(0) as u8) << 7; // (x_bytes[x_bytes.len()-1] & 1) << 7;
        y_bytes
    }

    pub fn secret_expand(k: [u8; 32]) -> (BigInt, [u8; 32]) {
        use sha2::Digest;
        use sha2::Sha512;
        let mut hasher = Sha512::new();

        hasher.update(&k);
        let finalized = hasher.finalize();
        let h = finalized.as_slice();
        let mut a = decode_little_endian(&h[..32]);
        a &= BigInt::pow(&BigInt::from(2), 254) - BigInt::from(8);
        a |= BigInt::pow(&BigInt::from(2), 254);

        let mut second_part = [0; 32];
        for i in 0..32 {
            second_part[i] = h[i + 32];
        }

        (a, second_part)
    }

    pub fn secret_to_public(secret: [u8; 32]) -> [u8; 32] {
        use super::ed25519::{point_mul, G};

        let (a, _) = secret_expand(secret);
        let point_result = point_mul(a.clone(), G.clone(), &P.clone(), &D.clone());
        compress_edward_point(point_result.0, point_result.1, point_result.2, P.clone())
    }
}

pub mod ed25519 {
    use super::info;

    use lazy_static::lazy_static;

    use super::num_bigint;
    use super::num_bigint::BigInt;

    pub type Point = (BigInt, BigInt, BigInt, BigInt);

    lazy_static! {
        pub static ref P: BigInt = BigInt::from_str_radix(
            "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed",
            16
        )
        .expect("Worked");
        pub static ref A24: BigInt = BigInt::from_str_radix("1db42", 16).expect("Worked");
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

    pub fn point_equal(pp: Point, qq: Point, p: &BigInt) -> bool {
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

    pub fn point_add(pp: Point, qq: Point, p: &BigInt, d: &BigInt) -> Point {
        // Compute a = ((pp.1 - pp.0) * (qq.1 - qq.0)) mod p
        let term1 = pp.1.mod_sub(&pp.0, p);
        let term2 = qq.1.mod_sub(&qq.0, p);
        let a = term1.mod_mul(&term2, p);

        // Compute b = ((pp.1 + pp.0) * (qq.1 + qq.0)) mod p
        let term3 = pp.1.mod_add(&pp.0, p);
        let term4 = qq.1.mod_add(&qq.0, p);
        let b = term3.mod_mul(&term4, p);

        // Compute c = (2 * pp.3 * qq.3 * d) mod p
        let two_pp3 = BigInt::from(2).mod_mul(&pp.3, p);
        let temp = two_pp3.mod_mul(&qq.3, p);
        let c = temp.mod_mul(d, p);

        // Compute d = (2 * pp.2 * qq.2) mod p
        let two_pp2 = BigInt::from(2).mod_mul(&pp.2, p);
        let d_val = two_pp2.mod_mul(&qq.2, p);

        let e = b.mod_sub(&a, p);
        let f = d_val.mod_sub(&c, p);
        let g = &d_val + &c;
        let h = &b + &a;

        let x3 = e.mod_mul(&f, p);
        let y3 = g.mod_mul(&h, p);
        let z3 = f.mod_mul(&g, p);
        let t3 = e.mod_mul(&h, p);

        (x3, y3, z3, t3)
    }

    pub fn point_mul(s: BigInt, pp: Point, p: &BigInt, d: &BigInt) -> Point {
        let mut pp = pp.clone();
        let mut q = (
            BigInt::from(0),
            BigInt::from(1),
            BigInt::from(1),
            BigInt::from(0),
        );
        let mut s = s;
        while s > BigInt::from(0) {
            if s.bit(0) == true {
                q = point_add(q.clone(), pp.clone(), p, d);
            }
            pp = point_add(pp.clone(), pp.clone(), p, d);
            s = s >> 1;
        }

        q
    }

    // Returns (X:Y:Z) representation in montgomery of the edward curve
    pub fn point_mul_sec(_s: BigInt, _pp: Point, _p: &BigInt, _d: &BigInt) -> Point {
        unimplemented!("Still not implemented")
    }

    use sha2::{Digest, Sha512};

    fn sha512_modq(msg: &[u8], q: &BigInt) -> BigInt {
        let finalized = Sha512::new().chain_update(msg).finalize();
        let hash = finalized.as_slice();

        let result_nomodq = BigInt::from_bytes_le(num_bigint::Sign::Plus, &hash[0..64]);

        result_nomodq % q
    }

    pub fn sign(secret: [u8; 32], msg: &[u8]) -> [u8; 64] {
        let p = P.clone();
        let d = D.clone();
        let q = Q.clone();

        let (a, prefix) = super::hex::secret_expand(secret);
        let intermediary_point = point_mul(a.clone(), G.clone(), &p, &d);
        let aa = super::hex::compress_edward_point(
            intermediary_point.0,
            intermediary_point.1,
            intermediary_point.2,
            p.clone(),
        );

        let prefix_h = prefix.as_slice();
        let mut storage = [0u8; 1024];
        let concatenated_message = super::concat_emul(&[prefix_h, msg], &mut storage);
        let r = sha512_modq(&concatenated_message, &q);
        let rr = point_mul(r.clone(), G.clone(), &p, &d);

        let rrs = super::hex::compress_edward_point(rr.0, rr.1, rr.2, p.clone());

        assert!(rrs.len() == 32);

        let mut storage = [0u8; 1024];
        let rrsamsg = super::concat_emul(&[&rrs, &aa, msg], &mut storage);
        let h = sha512_modq(&rrsamsg, &q);
        let s = (r + h * a) % &q;

        let sbytes = s.to_signed_bytes_le();
        let mut signature: [u8; 64] = [0; 64];

        for i in 0..32 {
            signature[i] = rrs[i];
        }

        for i in 32..(32 + sbytes.len()) {
            signature[i] = sbytes[i - 32];
        }

        for i in (32 + sbytes.len())..(64) {
            signature[i] = 0;
        }

        signature
    }

    pub fn verify(public: [u8; 32], msg: &[u8], signature: [u8; 64]) -> bool {
        let p = P.clone();
        let d = D.clone();
        let q = Q.clone();

        info!("Decompressing public key");
        let aa = super::hex::decompress_edward_point(public, p.clone(), d.clone());

        if aa == None {
            return false;
        }

        let aa = aa.unwrap();

        let rrs: [u8; 32] = signature[0..32]
            .try_into()
            .expect("Invalid signature length");

        info!("Decompressing rrs");
        let rr = super::hex::decompress_edward_point(rrs, p.clone(), d.clone());
        if rr == None {
            return false;
        }

        let rr = rr.unwrap();

        let s_bytes: [u8; 32] = signature[32..64]
            .try_into()
            .expect("invalid signature length");
        let s = super::hex::decode_little_endian(&s_bytes);

        if &s >= &q {
            return false;
        }

        let rrs = rrs.as_slice();
        let public = public.as_slice();
        let mut storage = [0u8; 128];
        let concat = super::concat_emul(&[rrs, public, msg], &mut storage);
        info!("Doing sha512_modq");
        let h = sha512_modq(&concat, &q);

        info!("Doing point_mul(s, G)");
        let sbb = point_mul(s, G.clone(), &p, &d);
        info!("Doing point_mul(h, aa)");
        let haa = point_mul(h, aa, &p, &d);
        info!("Doing point_add(rr, haa)");
        let second_point = point_add(rr, haa, &p, &d);
        info!("Doing point_equal(sbb, second_point, &p)");
        point_equal(sbb, second_point, &p)
    }
}
