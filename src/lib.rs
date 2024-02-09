extern crate lazy_static;
extern crate num_bigint;
extern crate bnum;

pub mod mathutils {
    use bnum::types::I512;

    // Credits to : https://docs.rs/modinverse/latest/src/modinverse/lib.rs.html
    fn egcd(a: I512, b: I512) -> (I512, I512, I512) {
        if a == I512::ZERO {
            (b, I512::ZERO, I512::ONE)
        }
        else {
            let (g, x, y) = egcd(b % a, a);
            (g, y - (b / a) * x, x)
        }
    }

    pub fn modinverse(a: I512, m: I512) -> Option<I512> {
        let (g, x, _) = egcd(a, m);
        if g != I512::ONE {
            None
        }
        else {
            Some((x % m + m) % m)
        }
    }
}

pub mod hex {

    use bnum::types::I512;
    // Extract the keys from the hex string
    pub fn decode_little_endian(b: &[u8]) -> Option<I512> {
        I512::from_le_slice(&b[0..32])
    }

    pub fn decode_scalar25519(k: &str) -> I512 {
        assert!(k.len() == 64);
        let mut k_list: [u8;32] = [0; 32];
        for i in 0..32 {
            k_list[i] = u8::from_str_radix(&k[2*i .. 2*(i+1)], 16).expect("Error parsing hexidecimal string");
        }
        
        k_list[0] &= 248;
        k_list[31] &= 127;
        k_list[31] |= 64;

        decode_little_endian(k_list.as_slice()).expect("Error parsing hex string")
    }

    
    pub fn decode_ucoordinate(k: &str) -> I512{
        assert!(k.len() == 64);
        let mut u_list: [u8;32] = [0; 32];
        for i in 0..32 {
            u_list[i] = u8::from_str_radix(&k[2*i .. 2*(i+1)], 16).expect("Error parsing hexidecimal string");
        }

        decode_little_endian(u_list.as_slice()).expect("Error parsing U coordinate")
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
    }

}

pub mod elliptic {

    use lazy_static::lazy_static;

    use bnum::types::I512;
    use super::mathutils::modinverse;


    lazy_static! {
        pub static ref P: I512 = I512::from(2).pow(255) - I512::from(19);
        pub static ref A24: I512 = I512::from(121666);
    }

    
    fn x_add(
        (x_p, z_p): (I512, I512),
        (x_q, z_q): (I512, I512),
        (x_m, z_m): (I512, I512),
        p: &I512,
    ) -> (I512, I512) {
        let p = *p;
        let u = ((&x_p - &z_p) * (&x_q + &z_q)).rem_euclid(p);
        let v = (&x_p + &z_p) * (&x_q - &z_q).rem_euclid(p);

        let upv2 = ((&u + &v).rem_euclid(p)).pow(2).rem_euclid(p);
        let umv2 = ((&u - &v).rem_euclid(p)).pow(2).rem_euclid(p);

        let x_p = ((&z_m).rem_euclid(p) * upv2).rem_euclid(p);
        let z_p = ((&x_m).rem_euclid(p) * umv2).rem_euclid(p);

        (x_p, z_p)
    }
    
    fn x_dbl((x, z): (I512, I512), p: &I512, a24: &I512) -> (I512, I512) {
        let p = *p;
        let q = (&x + &z).rem_euclid(p);
        let q = (q.pow(2)).rem_euclid(p);

        //let R = (X - Z) % p;
        let r = ((&x*&x)%p + (&z*&z)%p - (I512::from(2)*(((&x.rem_euclid(p))* (&z.rem_euclid(p))).rem_euclid(p)).rem_euclid(p)))%p;

        let s = (I512::from(4) * (((&x.rem_euclid(p)) * (&z.rem_euclid(p))).rem_euclid(p))).rem_euclid(p);

        let x_3 = (&q * &r).rem_euclid(p);
        let z_3 = (&s * (&r + (a24 * &s) %p).rem_euclid(p)).rem_euclid(p);

        (x_3, z_3)
    }


    
    fn conditional_swap(
        swap: u8,
        (x_1, z_1): (I512, I512),
        (x_2, z_2): (I512, I512),
    ) -> ((I512, I512), (I512, I512)) {
        let swap = I512::from(swap);
        let onemswap = I512::from(1) - &swap;
        (
            (&x_1 * &onemswap + &x_2 * &swap, &z_1 * &onemswap + &z_2 * &swap),
            (&x_1 * &swap + &x_2 * &onemswap, &z_1 * &swap + &z_2 * &onemswap),
        )
    }
    

    
    pub fn ladder(m: &I512, x: &I512, p: &I512, a24: &I512) -> (I512, I512) {
        let u = (x.clone(), I512::from(1));
        let mut x_0 = (I512::from(1), I512::from(0));
        let mut x_1 = u.clone();

        let mut bits: [u8; 256] = [0; 256];
        for i in 0..255 {
            bits[i] = m.bit(i as u32) as u8;
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
    
    pub fn slightly_different_x22519(m: &I512, x: &I512, p: &I512, a24: &I512) -> I512 {
        let u = (x.clone(), I512::from(1));
        let mut x_2 = (I512::from(1), I512::from(0));
        let mut x_3 = u.clone();

        let mut bits: [u8; 256] = [0; 256];
        for i in 0..255 {
            bits[i] = m.bit(i as u32) as u8;
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

        
        x_2.0 * (modinverse(x_2.1, p.clone()).expect("p is not prime")) % p
    }


    #[cfg(test)]
    mod tests {

        use super::*;

        #[test]
        fn test_ladder() {
            /*
            let p = I512::from(101);
            let a24 = I512::from(38);


            let (x_1, z_1) = x_dbl((I512::from(2),I512::from(1)), &p, &a24);
            let x_0 = x_1.clone() * modinverse(z_1, p.clone()).expect("p not prime") % &p;
            assert_eq!(x_0, I512::from(70), "2[P]");
            
            
            let (x_1, z_1) = ladder(&I512::from(3), &I512::from(2), &p, &a24);
            let x_0 = x_1.clone() * modinverse(z_1, p.clone()).expect("p not prime") % &p;
            assert_eq!(x_0, I512::from(59), "3[P]");


            let (x_1, z_1) = ladder(&I512::from(77), &I512::from(2), &p, &a24);
            let x_0 = x_1.clone() * modinverse(z_1, p.clone()).expect("p not prime") % &p;
            assert_eq!(x_0, I512::from(8), "77[P]");

            
            // Tests with p = 1009 and A=682
            let p = I512::from(1009);
            let a24 = I512::from(171);

            let x_p = I512::from(7);

            let ms = [2, 3, 5, 34, 104, 947];
            let asserts = [284, 759, 1000, 286, 810, 755].map(|v| I512::from(v));
            for i in 0..ms.len() {
                let (x_1, z_1) = ladder( &I512::from(ms[i]), &x_p, &p, &a24);
                let x_0 = x_1.clone() * modinverse(z_1, p.clone()).expect("p not prime") % &p;
                let m = ms[i];
                assert_eq!(x_0, asserts[i], "{m}[P]");
    
            }
            */
            
            // Tests for Curve25519

            let p = P.clone();
            let a24 = A24.clone();

            let x_p = I512::from(9);

            let (x_1, z_1) = ladder( &I512::from(7), &x_p, &p, &a24);
            let x_0 = x_1.clone() * modinverse(z_1, p.clone()).expect("p not prime") % &p;
            dbg!(x_0.to_str_radix(10));

            

        }
    }
}
