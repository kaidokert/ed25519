#![cfg_attr(not(feature = "std"), no_std)]

extern crate lazy_static;
extern crate sha2;

mod num_bigint;

#[cfg(feature = "std")]
use log::{info, debug, error, warn};
#[cfg(feature = "std")]
use std::println;

#[cfg(feature = "defmt")]
use defmt::{info, debug, error, warn, println};

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

    #[cfg(feature = "precomputed")]
    lazy_static! {
        pub static ref P: BigInt = BigInt::from_str_radix("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed", 16).expect("Worked");
        pub static ref A24: BigInt = BigInt::from_str_radix("1db42", 16).expect("Worked");
        pub static ref D: BigInt = BigInt::from_str_radix("52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3", 16).expect("Worked");
    }

    #[cfg(not(feature = "precomputed"))]
    lazy_static! {
        pub static ref P: BigInt = BigInt::from(2).pow(255) - BigInt::from(19);
        pub static ref A24: BigInt = BigInt::from(121666);
/*
        pub static ref D: BigInt = (BigInt::from(-121665)
            * modp_inv(&BigInt::from(121666), &P.clone()))
        .rem_euclid(&P.clone());
*/
        pub static ref D: BigInt = {
            let p = P.clone();
            // Replace -121665 with (P - 121665) to avoid negatives
            let numerator = &p - BigInt::from(121665); 
            let inv_121666 = modp_inv(&A24, &p); // A24 is 121666, so reuse it
            (numerator * inv_121666).rem_euclid(&p)
        };        
    }

    #[cfg(any(test,feature ="dump"))]
    pub fn dump_static_constants() {
        println!("hex: P: {:?}", P.clone().to_str_radix(16));
        println!("hex: A24: {:?}", A24.clone().to_str_radix(16));
        println!("hex: D: {:?}", D.clone().to_str_radix(16));
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
        let x2 = ((y * y - BigInt::from(1)) * modp_inv(&(&d * y * y + BigInt::from(1)), &p))
            .rem_euclid(&p);

        if x2 == 0.into() {
            if sign > 0 {
                None
            } else {
                Some(BigInt::from(0))
            }
        } else {
            let p3 = &p + BigInt::from(3);
            let mut x = x2.modpow(&p3.div_euclid(&BigInt::from(8)), &p);
            let modp_sqrt_m1 =
                BigInt::from(2).modpow(&((&p - BigInt::from(1)).div_euclid(&BigInt::from(4))), &p);

            if (&x * &x - &x2).rem_euclid(&p) != BigInt::from(0) {
                x = (&x * modp_sqrt_m1).rem_euclid(&p);
            }

            if (&x * &x - &x2).rem_euclid(&p) != BigInt::from(0) {
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
                return Some((
                    x.clone(),
                    y.clone(),
                    BigInt::from(1),
                    (x * y).rem_euclid(&p),
                ));
            }
        }
    }

    pub fn compress_edward_point(x: BigInt, y: BigInt, z: BigInt, p: BigInt) -> [u8; 32] {
        // No need to worry about t. Only provide x y and z.
        let zinv = modp_inv(&z, &p);
        let x = (x * &zinv).rem_euclid(&p);
        let y = (y * &zinv).rem_euclid(&p);

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

    #[cfg(feature = "precomputed")]
    lazy_static! {
        pub static ref P: BigInt = BigInt::from_str_radix("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed", 16).expect("Worked");
        pub static ref A24: BigInt = BigInt::from_str_radix("1db42", 16).expect("Worked");
        pub static ref D: BigInt = BigInt::from_str_radix("52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3", 16).expect("Worked");
        pub static ref G_Y: BigInt = BigInt::from_str_radix("6666666666666666666666666666666666666666666666666666666666666658", 16).expect("Worked");
        pub static ref G_X: BigInt = BigInt::from_str_radix("216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a", 16).expect("Worked");
        pub static ref G: Point = (
            G_X.clone(),
            G_Y.clone(),
            BigInt::from(1),
            BigInt::from_str_radix("67875f0fd78b766566ea4e8e64abe37d20f09f80775152f56dde8ab3a5b7dda3", 16).expect("Worked")
        );
        pub static ref Q: BigInt = BigInt::from_str_radix("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed", 16).expect("Worked");
    }

    #[cfg(not(feature = "precomputed"))]
    lazy_static! {
        pub static ref P: BigInt = BigInt::from(2).pow(255) - BigInt::from(19);
        pub static ref A24: BigInt = BigInt::from(121666);
/*
        pub static ref D: BigInt = (BigInt::from(-121665)
            * super::hex::modp_inv(&BigInt::from(121666), &P.clone()))
        .rem_euclid(&P.clone());
 */
        pub static ref D: BigInt = {
            let p = P.clone();
            // Replace -121665 with (P - 121665) to avoid negatives
            let numerator = &p - BigInt::from(121665); 
            let inv_121666 = super::hex::modp_inv(&A24, &p); // A24 is 121666, so reuse it
            (numerator * inv_121666).rem_euclid(&p)
        };        
        pub static ref G_Y: BigInt = (BigInt::from(4)
            * super::hex::modp_inv(&BigInt::from(5), &P.clone()))
        .rem_euclid(&P.clone());
        pub static ref G_X: BigInt = super::hex::recover_x(&G_Y.clone(), 0, P.clone(), D.clone())
            .expect("Error in recover_x or modp_inv");
        pub static ref G: Point = (
            G_X.clone(),
            G_Y.clone(),
            BigInt::from(1),
            (G_X.clone() * G_Y.clone()).rem_euclid(&P.clone())
        );
        pub static ref Q: BigInt = BigInt::from(2).pow(252)
            + BigInt::from_str_radix("27742317777372353535851937790883648493", 10)
                .expect("Error in group order q constant");
    }


    #[cfg(any(test,feature ="dump"))]
    pub fn dump_static_constants() {
        println!("P: {}", P.clone().to_str_radix(16));
        println!("A24: {}", A24.clone().to_str_radix(16));
        println!("D: {}", D.clone().to_str_radix(16));
        println!("G_Y: {}", G_Y.clone().to_str_radix(16));
        println!("G_X: {}", G_X.clone().to_str_radix(16));
        println!("Q: {}", Q.clone().to_str_radix(16));
        println!("G 0: {}", G.clone().0.to_str_radix(16));
        println!("G 1: {}", G.clone().1.to_str_radix(16));
        println!("G 2: {}", G.clone().2.to_str_radix(16));
        println!("G 3: {}", G.clone().3.to_str_radix(16));
    }

    pub fn point_equal(pp: Point, qq: Point, p: &BigInt) -> bool {
        let term1= &pp.0 * &qq.2;
        let term2 = &qq.0 * &pp.2;

        let term3 = &pp.1 * &qq.2;
        let term4 = &qq.1 * &pp.2;
        if (&term1.mod_sub(&term2, p)).rem_euclid(p) != BigInt::from(0) {
            false
        } else if (&term3.mod_sub(&term4, p)).rem_euclid(p) != BigInt::from(0) {
            false
        } else {
            true
        }
    }

    pub fn point_add(pp: Point, qq: Point, p: &BigInt, d: &BigInt) -> Point {
        // Compute a = ((pp.1 - pp.0) * (qq.1 - qq.0)) mod p
        let term1 = pp.1.mod_sub(&pp.0, p);
        let term2 = qq.1.mod_sub(&qq.0, p);
        let a = (term1 * term2).rem_euclid(p);

        // Compute b = ((pp.1 + pp.0) * (qq.1 + qq.0)) mod p
        let term3 = (&pp.1 + &pp.0).rem_euclid(p);
        let term4 = (&qq.1 + &qq.0).rem_euclid(p);
        let b = (term3 * term4).rem_euclid(p);

        // Compute c = (2 * pp.3 * qq.3 * d) mod p
        let c = (BigInt::from(2) * &pp.3 * &qq.3 * d).rem_euclid(p);

        // Compute d = (2 * pp.2 * qq.2) mod p
        let d_val = (BigInt::from(2) * &pp.2 * &qq.2).rem_euclid(p);

        let e = b.mod_sub(&a, p);
        let f = d_val.mod_sub(&c, p);
        let g = &d_val + &c;
        let h = &b + &a;

        (&e * &f, &g * &h, &f * &g, &e * &h)
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

        result_nomodq.rem_euclid(q)
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
        let s = (r + h * a).rem_euclid(&q);

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

pub mod elliptic {

    use lazy_static::lazy_static;

    use super::num_bigint::BigInt;

    #[cfg(not(feature = "precomputed"))]
    lazy_static! {
        pub static ref P: BigInt = BigInt::from(2).pow(255) - BigInt::from(19);
        pub static ref A24: BigInt = BigInt::from(121666);
    }

    #[cfg(feature = "precomputed")]
    lazy_static! {
        pub static ref P: BigInt = BigInt::from_str_radix("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed", 16).expect("Worked");
        pub static ref A24: BigInt = BigInt::from_str_radix("1db42", 16).expect("Worked");
    }

    #[cfg(any(test,feature ="dump"))]
    pub fn dump_static_constants() {
        println!("elliptic: P: {:?}", P.clone().to_str_radix(16));
        println!("elliptic: A24: {:?}", A24.clone().to_str_radix(16));
    }

    fn x_add(
        (x_p, z_p): (BigInt, BigInt),
        (x_q, z_q): (BigInt, BigInt),
        (x_m, z_m): (BigInt, BigInt),
        p: &BigInt,
    ) -> (BigInt, BigInt) {
        // Compute u = (x_p - z_p) * (x_q + z_q) mod p (with safe subtraction)
        let term1 = x_p.mod_sub( &z_p, p);
        let term2 = (&x_q + &z_q) % p; // Addition is safe since inputs are mod p
        let u = (term1 * term2) % p;

        // Compute v = (x_p + z_p) * (x_q - z_q) mod p (with safe subtraction)
        let term3 = (&x_p + &z_p) % p;
        let term4 = x_q.mod_sub(&z_q, p);
        let v = (term3 * term4) % p;

        // Compute upv² and umv² with safe operations
        let upv = u.mod_add(&v, p); // Ensure (u + v) mod p
        let umv = u.mod_sub( &v, p); // Ensure (u - v) mod p
        let upv2 = (&upv * &upv) % p; // upv² mod p
        let umv2 = (&umv * &umv) % p; // umv² mod p

        let x_p = (&z_m * upv2) % p;
        let z_p = (&x_m * umv2) % p;

        (x_p, z_p)
    }

    fn x_dbl((x, z): (BigInt, BigInt), p: &BigInt, a24: &BigInt) -> (BigInt, BigInt) {
        let q = (&x + &z) % p;
        let q = (q.pow(2)) % p;

        //let R = (X - Z) % p;
        let r = (&x * &x + &z * &z - BigInt::from(2) * &x * &z) % p;

        let s = (BigInt::from(4) * &x * &z) % p;

        let x_3 = (&q * &r) % p;
        let z_3 = (&s * (&r + (a24 * &s))) % p;

        (x_3, z_3)
    }

    fn conditional_swap(
        swap: u8,
        (x_1, z_1): (BigInt, BigInt),
        (x_2, z_2): (BigInt, BigInt),
    ) -> ((BigInt, BigInt), (BigInt, BigInt)) {
        let swap = BigInt::from(swap);
        let onemswap = BigInt::from(1) - &swap;
        (
            (
                &x_1 * &onemswap + &x_2 * &swap,
                &z_1 * &onemswap + &z_2 * &swap,
            ),
            (
                &x_1 * &swap + &x_2 * &onemswap,
                &z_1 * &swap + &z_2 * &onemswap,
            ),
        )
    }

    pub fn ladder(m: &BigInt, x: &BigInt, p: &BigInt, a24: &BigInt) -> (BigInt, BigInt) {
        let u = (x.clone(), BigInt::from(1));
        let mut x_0 = (BigInt::from(1), BigInt::from(0));
        let mut x_1 = u.clone();

        let mut bits: [u8; 256] = [0; 256];
        for i in 0..255 {
            bits[i] = m.bit(i as u64) as u8;
        } // Bits are read in one constant go.

        for i in (0..m.bits()).rev() {
            let bit = bits[i as usize];
            let x_added = x_add(x_0.clone(), x_1.clone(), u.clone(), p);
            let (m0, _) = conditional_swap(bit, x_0, x_1);
            let x_doubled = x_dbl(m0, &p, &a24);

            x_0 = x_doubled;
            x_1 = x_added;

            let (m0, m1) = conditional_swap(bit, x_0, x_1);

            x_0 = m0;
            x_1 = m1;
        }

        x_0
    }

    pub fn slightly_different_x22519(m: &BigInt, x: &BigInt, p: &BigInt, a24: &BigInt) -> BigInt {
        let u = (x.clone(), BigInt::from(1));
        let mut x_2 = (BigInt::from(1), BigInt::from(0));
        let mut x_3 = u.clone();

        let mut bits: [u8; 256] = [0; 256];
        for i in 0..255 {
            bits[i] = m.bit(i as u64) as u8;
        } // Bits are read in one constant go.
        let mut swap = 0;
        for i in (0..m.bits()).rev() {
            let bit = bits[i as usize];
            swap ^= bit;

            (x_2, x_3) = conditional_swap(swap, x_2, x_3);

            swap = bit;
            let xx_2 = &x_2.0;
            let xz_2 = &x_2.1;

            let xx_3 = &x_3.0;
            let xz_3 = &x_3.1;

            let a = xx_2 + xz_2;
            let aa = (&a).pow(2);

            let b = xx_2 - xz_2;
            let bb = (&b).pow(2);

            let e = &aa - &bb;
            let c = xx_3 + xz_3;
            let d = xx_3 - xz_3;
            let da = d * &a;
            let cb = c * &b;

            let xx_3 = (&da + &cb).pow(2) % p;
            let xz_3 = x * (&da - &cb).pow(2) % p;
            let xx_2 = (&aa * bb) % p;
            let xz_2 = &e * (aa + a24 * &e) % p;

            x_2 = (xx_2, xz_2);
            x_3 = (xx_3, xz_3);
        }
        (x_2, _) = conditional_swap(swap, x_2, x_3);

        x_2.0 * (x_2.1.modpow(&(p - 2), p)) % p
    }
}