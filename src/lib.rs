extern crate lazy_static;
extern crate num_bigint;
extern crate sha2;

pub mod hex {

    use num_bigint::BigInt;
    use num_traits::{Euclid, Num, ToBytes};

    use lazy_static::lazy_static;


    lazy_static! {
        pub static ref P: BigInt = BigInt::from(2).pow(255) - BigInt::from(19);
        pub static ref A24: BigInt = BigInt::from(121666);
        pub static ref D: BigInt = (BigInt::from(-121665) * modp_inv(&BigInt::from(121666), &P.clone())).rem_euclid(&P.clone());
    }


    // Extract the keys from the hex string
    pub fn decode(hexstr: &str) -> Result<BigInt, num_bigint::ParseBigIntError>{
        let r = BigInt::from_str_radix(hexstr, 16);
        r
    }

    pub fn hex64_to_vec32u8(hexstr: &str) -> [u8;32] {
        assert!(hexstr.len() == 64, "Hexidacimal string size is wrong");
        let mut k_list: [u8;32] = [0; 32];
        for i in 0..32 {
            k_list[i] = u8::from_str_radix(&hexstr[2*i .. 2*(i+1)], 16).expect("Error parsing hexidecimal string");
        }
        k_list

    }

    pub fn decode_little_endian(b: &[u8]) -> BigInt {
        BigInt::from_bytes_le(num_bigint::Sign::Plus, &b[0..32])
    }

    pub fn decode_scalar25519(k: &str) -> BigInt{
        let mut k_list: [u8; 32] = hex64_to_vec32u8(k);
        
        k_list[0] &= 248;
        k_list[31] &= 127;
        k_list[31] |= 64;

        decode_little_endian(k_list.as_slice())
    }

    
    pub fn decode_ucoordinate(k: &str) -> BigInt{
        let u_list: [u8; 32] = hex64_to_vec32u8(k);

        decode_little_endian(u_list.as_slice())
    }

    pub fn modp_inv(m: &BigInt, p: &BigInt) -> BigInt {
        m.modpow(&(p-BigInt::from(2)),  p)
    }

    // Verified function.
    pub fn recover_x(y: &BigInt, sign:u8, p: BigInt, d:BigInt) -> Option<BigInt> {
        let x2 = ((y * y - BigInt::from(1)) * modp_inv(&(&d * y * y + BigInt::from(1)), &p)) % &p;
        if x2 == 0.into() {
            if sign > 0 {
                None
            } else {
                Some(BigInt::from(0))
            }
        } else {
            let p3 = &p + BigInt::from(3);
            let mut x = x2.modpow( &p3.div_euclid(&BigInt::from(8)),  &p );
            let modp_sqrt_m1 = BigInt::from(2).modpow( &((&p - BigInt::from(1)).div_euclid(&BigInt::from(4))) , &p);
            

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
    
	pub fn decompress_edward_point(k: [u8;32], p:BigInt, d:BigInt) -> Option<(BigInt, BigInt, BigInt, BigInt)> {
        let mut k_list = k.clone();
        
        let sign = k_list[0] >> 3;
        k_list[0] &= 255;
        
        let y = decode_little_endian(&k_list);
        
        if &y > &p {
            return None;
        } else {
            let x = recover_x(&y, sign, p.clone(), d.clone());
            if x == None {
                return None;
            } else {
                let x = x.unwrap();
                return Some((x.clone(), y.clone(), BigInt::from(1), (x * y).rem_euclid(&p)));
            }
        }
    }

    pub fn compress_edward_point(x: BigInt, y:BigInt, z:BigInt, p:BigInt) -> Vec<u8> {
        // No need to worry about t. Only provide x y and z.
        let zinv = modp_inv(&z, &p);
        let x = (x * &zinv).rem_euclid(&p);
        let y = (y * &zinv).rem_euclid(&p);

        let x_bytes = x.to_le_bytes();
        let mut y_bytes = y.to_le_bytes();

        y_bytes[0] |= x_bytes[0] & 0x80;
        
        y_bytes
        
    }

    pub fn secret_expand(k: [u8; 32]) -> (BigInt, [u8; 32]) {
        use sha2::Digest;
        use sha2::Sha512;
        let mut hasher = Sha512::new();

        hasher.update(&k);
        let h =hasher.finalize().to_vec();
        let mut a = decode_little_endian(&h[..32]);
        a &= BigInt::pow(&BigInt::from(2), 254) - BigInt::from(8);
        a |= BigInt::pow(&BigInt::from(2), 254);

        let mut second_part = [0; 32];
        for i in 0..32 {
            second_part[i] = h[i+32];
        }

        (a, second_part)
    }

    pub fn secret_to_public(secret: [u8; 32]) -> Vec<u8> {
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
            let public = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a".to_string();
            let public_bytes = hex64_to_vec32u8(&public);
            let (x, y, z, t) = decompress_edward_point(public_bytes, P.clone(), D.clone()).expect("problem decompressing");
            dbg!(x, y, z, t);
            // Should find (38815646466658113194383306759739515082307681141926459231621296960732224964046, 11903303657706407974989296177215005343713679411332034699907763981919547054807, 1, 31275909032640112889229532081174740659065478602231738919115306243253221725764)
        }

        #[test]
        fn test_compress() {
            let public = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a".to_string();
            let public_bytes = hex64_to_vec32u8(public.as_str());

            let (x, y, z, _t) = decompress_edward_point(public_bytes, P.clone(), D.clone()).expect("problem decompressing");
            
            let compression = compress_edward_point(x, y, z, P.clone());
            
            for i in 0..compression.len() {
                print!("{:x}", compression[i])
            }
            println!();
            // Verify they are equal.
        }

        
        #[test]
        fn test_secret_expand() {
            let secret = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a".to_string();

            let secret_bytes = hex64_to_vec32u8(&secret);
            let (a, rest) = secret_expand(secret_bytes);
            dbg!(a, rest);

            // Should find : 
            // 33030247821042949592928462617058391656238976103718627791325708308254774592008
            // [71, 9, 104, 130, 147, 196, 121, 192, 83, 77, 239, 211, 169, 139, 67, 2, 24, 120, 6, 81, 27, 131, 241, 42, 181, 117, 212, 20, 71, 112, 169, 195]
        }

        #[test]
        fn test_secret_to_public() {
            let secret = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a".to_string();

            let secret_bytes = hex64_to_vec32u8(&secret);
            let result = secret_to_public(secret_bytes);
            dbg!(result);
            // Result should give : [19, 76, 116, 90, 206, 6, 133, 104, 78, 255, 48, 104, 83, 38, 139, 110, 234, 130, 207, 168, 67, 118, 173, 117, 22, 221, 67, 129, 183, 189, 203, 217]
            // Note : this verifies both point_mul and point_add.
        }
    }

}

pub mod ed25519 {

    use lazy_static::lazy_static;

    use num_bigint::BigInt;
    use num_traits::{Euclid, Num};

    pub type Point = (BigInt, BigInt, BigInt, BigInt);


    lazy_static! {
        pub static ref P: BigInt = BigInt::from(2).pow(255) - BigInt::from(19);
        pub static ref A24: BigInt = BigInt::from(121666);
        pub static ref D: BigInt = (BigInt::from(-121665) * super::hex::modp_inv(&BigInt::from(121666), &P.clone())).rem_euclid(&P.clone());
        pub static ref G_Y: BigInt= (BigInt::from(4) * super::hex::modp_inv(&BigInt::from(5), &P.clone())).rem_euclid(&P.clone());
        pub static ref G_X: BigInt = super::hex::recover_x(&G_Y.clone(), 0, P.clone(), D.clone()).expect("Error in recover_x or modp_inv");
        pub static ref G: Point = (G_X.clone(), G_Y.clone(), BigInt::from(1), (G_X.clone() * G_Y.clone()).rem_euclid(&P.clone()));
        pub static ref Q: BigInt = BigInt::from(2).pow(252) + BigInt::from_str_radix("27742317777372353535851937790883648493", 10).expect("Error in group order q constant");
    }

    pub fn point_equal( pp : Point, qq : Point, p: &BigInt) -> bool {
        if (pp.0 * &qq.2 - qq.0 * &pp.2) % p != BigInt::from(0) {
            false
        } else if (pp.1 * qq.2 - qq.1 * pp.2) % p != BigInt::from(0) {
            false
        } else {
            true
        }
    }

    pub fn point_add( pp: Point, qq: Point, p: &BigInt, d: &BigInt) -> Point {
        let a = ((&pp.1 - &pp.0) * (&qq.1 - &qq.0)).rem_euclid(p) ;
        let b = ((pp.1 + pp.0) * (qq.1 + qq.0)).rem_euclid(p) ;
        let c = (BigInt::from(2) * pp.3 * qq.3 * d).rem_euclid(p);
        let d = (BigInt::from(2) * pp.2 * qq.2).rem_euclid(p);

        let e = &b - &a;
        let f = &d - &c;
        let g = d + c;
        let h = b + a;

        (&e * &f, &g * &h, &f * &g, &e * &h)
    }

    pub fn point_mul(s: BigInt, pp: Point, p: &BigInt, d: &BigInt) -> Point {
        let mut pp = pp.clone();
        let mut q = (BigInt::from(0), BigInt::from(1), BigInt::from(1), BigInt::from(0));
        let mut s = s;
        while &s > &BigInt::from(0) {
            if s.bit(0) == true {
                q = point_add(q.clone(), pp.clone(), p, d);
            }
            pp = point_add(pp.clone(), pp.clone(), p, d);
            s = s >> 1;
        }

        q
    }

    fn sha512_modq(msg:&[u8], q: &BigInt) -> BigInt {
        use sha2::Digest;
        use sha2::Sha512;
        let mut hasher = Sha512::new();

        hasher.update(msg);
        let h =hasher.finalize().to_vec();
        let result_nomodq = BigInt::from_bytes_le(num_bigint::Sign::Plus, &h[0..64]);

        result_nomodq.rem_euclid(q)
    }

    pub fn sign(secret: [u8;32], msg:&[u8]) -> [u8; 64] {
        let p = P.clone();
        let d = D.clone();
        let q = Q.clone();
        let (a, prefix) = super::hex::secret_expand(secret);
        let intermediary_point = point_mul(a.clone(), G.clone(), &p, &d);
        let aa = super::hex::compress_edward_point(intermediary_point.0, intermediary_point.1, intermediary_point.2, p.clone());

        let concatenated_message = [&prefix, msg].concat();
        let r = sha512_modq(&concatenated_message, &q);
        let rr = point_mul(r.clone(), G.clone(), &p, &d);
        let rrs = super::hex::compress_edward_point(rr.0, rr.1, rr.2, p.clone());
        assert!(rrs.len() == 32);

        let rrsamsg = [&rrs, &aa, msg].concat();
        let h = sha512_modq(&rrsamsg, &q);

        let s = (r + h * a).rem_euclid(&q);

        let sbytes = s.to_signed_bytes_le();
        let mut signature:[u8; 64] = [0; 64];
        
        for i in 0..32 {
            signature[i] = rrs[i];
        }

        for i in 32..64 {
            signature[i] = sbytes[i-32];
        }

        signature


    }

    pub fn verify(public: [u8; 32], msg:&[u8], signature: [u8; 64]) -> bool {
        let p = P.clone();
        let d = D.clone();
        let q = Q.clone();

        let aa = super::hex::decompress_edward_point(public, p.clone(), d.clone());

        if aa == None {
            return false;
        }
        
        let aa = aa.unwrap();

        let rrs : [u8; 32] = signature[0..32].try_into().expect("Invalid signature length");
        let rr = super::hex::decompress_edward_point(rrs, p.clone() , d.clone());

        if rr == None {return false;}
        let rr = rr.unwrap();

        let s_bytes:[u8; 32] = signature[32..64].try_into().expect("invalid signature length");
        let s = super::hex::decode_little_endian(&s_bytes);

        if &s >= &q {
            return false;
        }

        let h = sha512_modq(&[&rrs, &public, msg].concat(), &q);
        let sbb = point_mul(s, G.clone(), &p, &d);
        let haa = point_mul(h, aa, &p, &d);

        point_equal(sbb, point_add(rr, haa, &p, &d), &p)
    }

    #[cfg(test)]
    mod tests {

        use super::*;

        #[test]
        fn values_of_g() {
            dbg!(G.clone());
            // Should give : (15112221349535400772501151409588531511454012693041857206046113283949847762202, 46316835694926478169428394003475163141307993866256225615783033603165251855960, 1, 46827403850823179245072216630277197565144205554125654976674165829533817101731)
        }


    }

}

pub mod elliptic {

    use lazy_static::lazy_static;

    use num_bigint::BigInt;

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
        let u = (&x_p - &z_p) * (&x_q + &z_q) % p;
        let v = (&x_p + &z_p) * (&x_q - &z_q) % p;

        let upv2 = (&u + &v).pow(2);
        let umv2 = (&u - &v).pow(2);

        let x_p = (&z_m * upv2) % p;
        let z_p = (&x_m * umv2) % p;

        (x_p, z_p)
    }
    
    fn x_dbl((x, z): (BigInt, BigInt), p: &BigInt, a24: &BigInt) -> (BigInt, BigInt) {

        let q = (&x + &z) % p;
        let q = (q.pow(2)) % p;

        //let R = (X - Z) % p;
        let r = (&x*&x + &z*&z - BigInt::from(2)*&x*&z) % p;

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
            (&x_1 * &onemswap + &x_2 * &swap, &z_1 * &onemswap + &z_2 * &swap),
            (&x_1 * &swap + &x_2 * &onemswap, &z_1 * &swap + &z_2 * &onemswap),
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
        let mut swap= 0;
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
            let xz_3 = x * (&da - &cb ).pow(2) % p;
            let xx_2 = (&aa * bb) % p;
            let xz_2 = &e * (aa + a24 * &e) % p;

            x_2 = (xx_2, xz_2);
            x_3 = (xx_3, xz_3);

        }
        (x_2, _) = conditional_swap(swap, x_2, x_3);

        x_2.0 * (x_2.1.modpow(&(p-2), p)) % p
    }


    #[cfg(test)]
    mod tests {

        use super::*;

        #[test]
        fn test_ladder() {
            let p = BigInt::from(101);
            let a24 = BigInt::from(38);


            let (x_1, z_1) = x_dbl((BigInt::from(2),BigInt::from(1)), &p, &a24);
            let x_0 = (x_1.clone() * BigInt::modpow(&z_1, &(&p-BigInt::from(2)), &p)) % (&p);
            assert_eq!(x_0, BigInt::from(70), "2[P]");


            let (x_1, z_1) = ladder(&BigInt::from(3), &BigInt::from(2), &p, &a24);
            let x_0 = (x_1.clone() * BigInt::modpow(&z_1, &(&p-BigInt::from(2)), &p)) % (&p);
            assert_eq!(x_0, BigInt::from(59), "3[P]");


            let (x_1, z_1) = ladder(&BigInt::from(77), &BigInt::from(2), &p, &a24);
            let x_0 = (x_1.clone() * BigInt::modpow(&z_1, &(&p-BigInt::from(2)), &p)) % (&p);
            assert_eq!(x_0, BigInt::from(8), "77[P]");


            // Tests with p = 1009 and A=682
            let p = BigInt::from(1009);
            let a24 = BigInt::from(171);

            let x_p = BigInt::from(7);

            let ms = [2, 3, 5, 34, 104, 947];
            let asserts = [284, 759, 1000, 286, 810, 755].map(|v| BigInt::from(v));
            for i in 0..ms.len() {
                let (x_1, z_1) = ladder( &BigInt::from(ms[i]), &x_p, &p, &a24);
                let x_0 = (x_1.clone() * BigInt::modpow(&z_1, &(&p-BigInt::from(2)), &p)) % (&p);
                assert_eq!(x_0, asserts[i], "{i}[P]");
    
            }

            
            // Tests for Curve25519

            let p = P.clone();
            let a24 = A24.clone();

            let x_p = BigInt::from(9);

            let (x_1, z_1) = ladder( &BigInt::from(7), &x_p, &p, &a24);
            let x_0 = (x_1.clone() * BigInt::modpow(&z_1, &(&p-BigInt::from(2)), &p)) % (&p);
            dbg!(x_0.to_str_radix(10));


        }
    }
}
