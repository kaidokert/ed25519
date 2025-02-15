#![cfg_attr(not(feature = "std"), no_std)]

extern crate lazy_static;
extern crate sha2;

mod num_bigint;

pub mod hex {

    use super::num_bigint;
    use num_bigint::BigInt;

    use lazy_static::lazy_static;

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
        let h = hasher.finalize().to_vec();
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

    #[cfg(test)]
    mod tests {

        use super::*;

        #[test]
        fn test_ladder() {
            let k = "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4".to_string();
            let u = "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c".to_string();

            let k = decode_scalar25519(&k);
            let u = decode_ucoordinate(&u);
            dbg!(k, u);
        }

        #[test]
        fn test_decompress() {
            let public =
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a".to_string();
            let public_bytes = hex64_to_vec32u8(&public);
            let (x, y, z, t) = decompress_edward_point(public_bytes, P.clone(), D.clone())
                .expect("problem decompressing");
            dbg!(x, y, z, t);
            // Should find (38815646466658113194383306759739515082307681141926459231621296960732224964046, 11903303657706407974989296177215005343713679411332034699907763981919547054807, 1, 31275909032640112889229532081174740659065478602231738919115306243253221725764)

            // Second test :
            let public_bytes: [u8; 32] = [
                199, 190, 9, 46, 161, 6, 20, 21, 2, 22, 174, 144, 46, 149, 203, 174, 182, 63, 225,
                133, 40, 152, 222, 115, 27, 151, 250, 182, 75, 244, 176, 232,
            ];
            let (x, y, z, t) = decompress_edward_point(public_bytes, P.clone(), D.clone())
                .expect("problem decompressing");
            dbg!(x, y, z, t);
            // Should find (30075932235477025684340298072527288884134191593746418931107004766826760085331, 47353187403435240905172017119993343428085915786025168596961101668974187888327, 1, 33002513719147322511145294300392920129411559142076362960813597764447185691818)
        }

        #[test]
        fn test_recover_x() {
            let y = BigInt::from_str_radix(
                "47353187403435240905172017119993343428085915786025168596961101668974187888327",
                10,
            )
            .expect("Processing failed");
            let sign = 1;

            let x = recover_x(&y, sign, P.clone(), D.clone());

            dbg!(x);
        }

        #[test]
        fn test_compress() {
            let public =
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a".to_string();
            let public_bytes = hex64_to_vec32u8(public.as_str());

            let (x, y, z, _t) = decompress_edward_point(public_bytes, P.clone(), D.clone())
                .expect("problem decompressing");

            let compression = compress_edward_point(x, y, z, P.clone());

            for i in 0..compression.len() {
                print!("{:x}", compression[i])
            }
            println!();
            // Verify they are equal.
        }

        #[test]
        fn test_secret_expand() {
            let secret =
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a".to_string();

            let secret_bytes = hex64_to_vec32u8(&secret);
            let (a, rest) = secret_expand(secret_bytes);
            dbg!(a, rest);

            // Should find :
            // 33030247821042949592928462617058391656238976103718627791325708308254774592008
            // [71, 9, 104, 130, 147, 196, 121, 192, 83, 77, 239, 211, 169, 139, 67, 2, 24, 120, 6, 81, 27, 131, 241, 42, 181, 117, 212, 20, 71, 112, 169, 195]
        }

        #[test]
        fn test_secret_to_public() {
            let secret =
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a".to_string();

            let secret_bytes = hex64_to_vec32u8(&secret);
            let result = secret_to_public(secret_bytes);

            dbg!(&result);
            // Result should give : [19, 76, 116, 90, 206, 6, 133, 104, 78, 255, 48, 104, 83, 38, 139, 110, 234, 130, 207, 168, 67, 118, 173, 117, 22, 221, 67, 129, 183, 189, 203, 217]
            // Note : this verifies both point_mul and point_add.

            let pnt =
                decompress_edward_point(result.try_into().expect("huh???"), P.clone(), D.clone());
            dbg!(pnt);
            // Should be : (2921902947839513732129352123028044305513164824253249408160321654968707072031, 40615822855403707190122639951556956756078752302420076973416157483871956651027, 1, 39114520904941220745896610849441045036820856887057083606978905520513821263531)
        }
    }
}

pub mod ed25519 {

    use lazy_static::lazy_static;

    use super::num_bigint;
    use super::num_bigint::BigInt;

    pub type Point = (BigInt, BigInt, BigInt, BigInt);

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

    pub fn point_equal(pp: Point, qq: Point, p: &BigInt) -> bool {
        fn modular_subtract(a: &BigInt, b: &BigInt, p: &BigInt) -> BigInt {
            a.mod_sub(b, p)
        }
        let term1= &pp.0 * &qq.2;
        let term2 = &qq.0 * &pp.2;

        let term3 = &pp.1 * &qq.2;
        let term4 = &qq.1 * &pp.2;
        if (modular_subtract(&term1 , &term2, p)).rem_euclid(p) != BigInt::from(0) {
            false
        } else if (modular_subtract(&term3 , &term4, p)).rem_euclid(p) != BigInt::from(0) {
            false
        } else {
            true
        }
    }

    pub fn point_add(pp: Point, qq: Point, p: &BigInt, d: &BigInt) -> Point {
        fn modular_subtract(a: &BigInt, b: &BigInt, p: &BigInt) -> BigInt {
            a.mod_sub(b, p)
        }
        // Compute a = ((pp.1 - pp.0) * (qq.1 - qq.0)) mod p
        let term1 = modular_subtract(&pp.1, &pp.0, p);
        let term2 = modular_subtract(&qq.1, &qq.0, p);
        let a = (term1 * term2).rem_euclid(p);

        // Compute b = ((pp.1 + pp.0) * (qq.1 + qq.0)) mod p
        let term3 = (&pp.1 + &pp.0).rem_euclid(p);
        let term4 = (&qq.1 + &qq.0).rem_euclid(p);
        let b = (term3 * term4).rem_euclid(p);

        // Compute c = (2 * pp.3 * qq.3 * d) mod p
        let c = (BigInt::from(2) * &pp.3 * &qq.3 * d).rem_euclid(p);

        // Compute d = (2 * pp.2 * qq.2) mod p
        let d_val = (BigInt::from(2) * &pp.2 * &qq.2).rem_euclid(p);

        let e = modular_subtract(&b, &a, p);
        let f = modular_subtract(&d_val, &c, p);
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
        let hash = Sha512::new().chain_update(msg).finalize().to_vec();

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
        let concatenated_message = [prefix_h, msg].concat();
        let r = sha512_modq(&concatenated_message, &q);
        let rr = point_mul(r.clone(), G.clone(), &p, &d);

        let rrs = super::hex::compress_edward_point(rr.0, rr.1, rr.2, p.clone());

        assert!(rrs.len() == 32);

        let rrsamsg = [&rrs, &aa, msg].concat();
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

        let aa = super::hex::decompress_edward_point(public, p.clone(), d.clone());

        if aa == None {
            return false;
        }

        let aa = aa.unwrap();

        let rrs: [u8; 32] = signature[0..32]
            .try_into()
            .expect("Invalid signature length");

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
        let concat = [rrs, public, msg].concat();

        let h = sha512_modq(&concat, &q);

        let sbb = point_mul(s, G.clone(), &p, &d);
        let haa = point_mul(h, aa, &p, &d);

        let second_point = point_add(rr, haa, &p, &d);

        point_equal(sbb, second_point, &p)
    }

    #[cfg(test)]
    mod tests {

        use super::*;

        #[test]
        fn values_of_g() {
            dbg!(G.clone());
            // Should give : (15112221349535400772501151409588531511454012693041857206046113283949847762202, 46316835694926478169428394003475163141307993866256225615783033603165251855960, 1, 46827403850823179245072216630277197565144205554125654976674165829533817101731)
        }

        #[test]
        fn test_sign() {
            // Test with the example from the RFC 8032
            let secret: String =
                "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60".to_string();
            let secret_bytes = super::super::hex::hex64_to_vec32u8(&secret);

            let msg = "".to_string();
            let msg_bytes = msg.as_bytes();

            let result = sign(secret_bytes, &msg_bytes);
            for i in 0..32 {
                print!("{:x}{:x}", result[2 * i], result[2 * i + 1]);
            }
            println!();
            // Must find : [41, 253, 238, 26, 217, 201, 193, 232, 235, 246, 100, 41, 219, 40, 97, 99, 89, 72, 44, 136, 132, 13, 107, 71, 82, 127, 103, 238, 58, 229, 58, 1, 206, 147, 235, 31, 24, 80, 133, 202, 28, 70, 80, 37, 83, 215, 81, 177, 3, 203, 198, 156, 153, 19, 166, 178, 45, 74, 96, 200, 24, 163, 73, 7]
        }

        #[test]
        fn test_verify() {
            // Test with the example from the RFC 8032
            let secret =
                "bce7e3762feea90e5a5368046ee13e174681c5c9fda35a4fa57128e1de890472".to_string();
            let secret_bytes = super::super::hex::hex64_to_vec32u8(&secret);

            let public = super::super::hex::secret_to_public(secret_bytes);

            let msg = "Whatever  message you can find.".to_string();
            let msg = msg.as_bytes();

            let result = sign(secret_bytes, &msg);

            let verification = verify(
                public.try_into().expect("Unexpected, should be 32 bytes"),
                &msg,
                result,
            );
            dbg!(verification);
        }
    }
}

pub mod elliptic {

    use lazy_static::lazy_static;

    use super::num_bigint::BigInt;

    lazy_static! {
        pub static ref P: BigInt = BigInt::from(2).pow(255) - BigInt::from(19);
        pub static ref A24: BigInt = BigInt::from(121666);
    }

    fn x_add(
        (x_p, z_p): (BigInt, BigInt),
        (x_q, z_q): (BigInt, BigInt),
        (x_m, z_m): (BigInt, BigInt),
        p: &BigInt,
    ) -> (BigInt, BigInt) {
        // Helper for modular addition (not strictly needed here but included for completeness)
        fn modular_add(a: &BigInt, b: &BigInt, p: &BigInt) -> BigInt {
            a.mod_add(b, p)
        }
        fn modular_subtract(a: &BigInt, b: &BigInt, p: &BigInt) -> BigInt {
            a.mod_sub(b, p)
        }

        // Compute u = (x_p - z_p) * (x_q + z_q) mod p (with safe subtraction)
        let term1 = modular_subtract(&x_p, &z_p, p);
        let term2 = (&x_q + &z_q) % p; // Addition is safe since inputs are mod p
        let u = (term1 * term2) % p;

        // Compute v = (x_p + z_p) * (x_q - z_q) mod p (with safe subtraction)
        let term3 = (&x_p + &z_p) % p;
        let term4 = modular_subtract(&x_q, &z_q, p);
        let v = (term3 * term4) % p;

        // Compute upv² and umv² with safe operations
        let upv = modular_add(&u, &v, p); // Ensure (u + v) mod p
        let umv = modular_subtract(&u, &v, p); // Ensure (u - v) mod p
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

    #[cfg(test)]
    mod tests {

        use super::*;

        #[test]
        fn test_ladder() {
            let p = BigInt::from(101);
            let a24 = BigInt::from(38);

            let (x_1, z_1) = x_dbl((BigInt::from(2), BigInt::from(1)), &p, &a24);
            let x_0 = (x_1.clone() * BigInt::modpow(&z_1, &(&p - BigInt::from(2)), &p)) % (&p);
            assert_eq!(x_0, BigInt::from(70), "2[P]");

            let (x_1, z_1) = ladder(&BigInt::from(3), &BigInt::from(2), &p, &a24);
            let x_0 = (x_1.clone() * BigInt::modpow(&z_1, &(&p - BigInt::from(2)), &p)) % (&p);
            assert_eq!(x_0, BigInt::from(59), "3[P]");

            let (x_1, z_1) = ladder(&BigInt::from(77), &BigInt::from(2), &p, &a24);
            let x_0 = (x_1.clone() * BigInt::modpow(&z_1, &(&p - BigInt::from(2)), &p)) % (&p);
            assert_eq!(x_0, BigInt::from(8), "77[P]");

            // Tests with p = 1009 and A=682
            let p = BigInt::from(1009);
            let a24 = BigInt::from(171);

            let x_p = BigInt::from(7);

            let ms = [2, 3, 5, 34, 104, 947];
            let asserts = [284, 759, 1000, 286, 810, 755].map(|v| BigInt::from(v));
            for i in 0..ms.len() {
                let (x_1, z_1) = ladder(&BigInt::from(ms[i]), &x_p, &p, &a24);
                let x_0 = (x_1.clone() * BigInt::modpow(&z_1, &(&p - BigInt::from(2)), &p)) % (&p);
                assert_eq!(x_0, asserts[i], "{i}[P]");
            }

            // Tests for Curve25519

            let p = P.clone();
            let a24 = A24.clone();

            let x_p = BigInt::from(9);

            let (x_1, z_1) = ladder(&BigInt::from(7), &x_p, &p, &a24);
            let x_0 = (x_1.clone() * BigInt::modpow(&z_1, &(&p - BigInt::from(2)), &p)) % (&p);
            dbg!(x_0.to_str_radix(10));
        }
    }
}
