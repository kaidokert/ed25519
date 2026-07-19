//! `x25519_blinded` must match `x25519` for any curve-subgroup `u`.
//! A divergence here is a crypto break, not just a leak.

#![cfg(feature = "fixed-bigint")]

use const_num_traits::Ct;
use ed25519_heapless::{x25519, x25519_base, x25519_base_blinded, x25519_blinded};
use fixed_bigint::FixedUInt;
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;

type T = FixedUInt<u32, 16, Ct>;

const N_TRIALS: usize = 50;

fn deterministic_bytes(seed: u64, salt: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = ((seed.wrapping_mul(i as u64 + 1)) as u8) ^ salt ^ (i as u8);
    }
    out
}

#[test]
fn blinded_matches_unblinded_x25519() {
    let mut rng = ChaCha20Rng::seed_from_u64(0xed_25519_b1_1d);

    for trial in 0..N_TRIALS {
        let k = deterministic_bytes(trial as u64, 0xa5);
        let peer_secret = deterministic_bytes(trial as u64, 0x5a);
        let u = x25519_base::<T>(&peer_secret).unwrap();

        let unblinded = x25519::<T>(&k, &u).unwrap();
        let blinded = x25519_blinded::<T, _>(&mut rng, &k, &u).unwrap();

        assert_eq!(blinded, unblinded, "trial {trial} diverged");
    }
}

#[test]
fn blinded_matches_unblinded_x25519_base() {
    let mut rng = ChaCha20Rng::seed_from_u64(0xed_25519_ba_5e);

    for trial in 0..N_TRIALS {
        let k = deterministic_bytes(trial as u64, 0xc3);

        let unblinded = x25519_base::<T>(&k).unwrap();
        let blinded = x25519_base_blinded::<T, _>(&mut rng, &k).unwrap();

        assert_eq!(blinded, unblinded, "trial {trial} diverged");
    }
}

#[test]
fn blinded_with_zero_blinder_matches_unblinded() {
    // r = 0 → k' = k zero-extended; exercises the wider ladder loop's
    // leading-zero iterations.
    struct ZeroRng;
    impl rand_chacha::rand_core::TryRng for ZeroRng {
        type Error = core::convert::Infallible;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(0)
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(0)
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
            dest.fill(0);
            Ok(())
        }
    }
    impl rand_chacha::rand_core::TryCryptoRng for ZeroRng {}

    let k = deterministic_bytes(0x42, 0xff);
    let u = deterministic_bytes(0x42, 0x01);

    let unblinded = x25519::<T>(&k, &u).unwrap();
    let blinded = x25519_blinded::<T, _>(&mut ZeroRng, &k, &u).unwrap();

    assert_eq!(blinded, unblinded);
}

#[test]
fn blinded_with_max_blinder_matches_unblinded() {
    // r = u32::MAX exercises full-carry propagation through the
    // schoolbook multiply and the high end of the 544-bit ladder loop.
    struct MaxRng;
    impl rand_chacha::rand_core::TryRng for MaxRng {
        type Error = core::convert::Infallible;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(u32::MAX)
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(u64::MAX)
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
            dest.fill(0xff);
            Ok(())
        }
    }
    impl rand_chacha::rand_core::TryCryptoRng for MaxRng {}

    let k = deterministic_bytes(0xaa, 0x55);
    let peer_secret = deterministic_bytes(0xaa, 0xa5);
    let u = x25519_base::<T>(&peer_secret).unwrap();

    let unblinded = x25519::<T>(&k, &u).unwrap();
    let blinded = x25519_blinded::<T, _>(&mut MaxRng, &k, &u).unwrap();

    assert_eq!(blinded, unblinded);
}

#[test]
fn blinded_with_lambda_equal_to_p_matches_unblinded() {
    // RNG feeds P_BYTES for the projective rerand λ bytes. After mask
    // bytes[31] &= 0x7f, λ_t equals p exactly (p's high bit is 0
    // already). field.reduce(p) == 0, so without the CT is_p check
    // the ladder would degenerate to (0, 0, 0, 0) and diverge.
    use ed25519_heapless::P_BYTES;
    struct PRng {
        scalar_done: bool,
    }
    impl rand_chacha::rand_core::TryRng for PRng {
        type Error = core::convert::Infallible;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            self.scalar_done = true;
            Ok(0x1234_5678)
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(0)
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
            assert!(self.scalar_done && dest.len() == 32);
            dest.copy_from_slice(&P_BYTES);
            Ok(())
        }
    }
    impl rand_chacha::rand_core::TryCryptoRng for PRng {}

    let k = deterministic_bytes(0x99, 0x33);
    let peer_secret = deterministic_bytes(0x99, 0x66);
    let u = x25519_base::<T>(&peer_secret).unwrap();

    let unblinded = x25519::<T>(&k, &u).unwrap();
    let blinded = x25519_blinded::<T, _>(&mut PRng { scalar_done: false }, &k, &u).unwrap();

    assert_eq!(blinded, unblinded);
}

#[test]
fn blinded_produces_varying_intermediate_with_different_rng() {
    let mut rng_a = ChaCha20Rng::seed_from_u64(1);
    let mut rng_b = ChaCha20Rng::seed_from_u64(2);

    let k = deterministic_bytes(99, 0x77);
    let peer_secret = deterministic_bytes(99, 0x88);
    let u = x25519_base::<T>(&peer_secret).unwrap();

    let unblinded = x25519::<T>(&k, &u).unwrap();
    let from_a = x25519_blinded::<T, _>(&mut rng_a, &k, &u).unwrap();
    let from_b = x25519_blinded::<T, _>(&mut rng_b, &k, &u).unwrap();

    assert_eq!(from_a, unblinded);
    assert_eq!(from_b, unblinded);
}
