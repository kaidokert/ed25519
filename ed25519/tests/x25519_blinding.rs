//! `x25519_blinded` must match `x25519` for any curve-subgroup `u`.
//! A divergence here is a crypto break, not just a leak.

#![cfg(feature = "fixed-bigint")]

use ed25519_heapless::{x25519, x25519_base, x25519_base_blinded, x25519_blinded};
use fixed_bigint::{Ct, FixedUInt};
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
    // `u` must be a subgroup point for the `8·ℓ` blinding identity to
    // hold. Random 32-byte bytes land on the twist ~half the time;
    // derive `u` via `x25519_base` instead.
    let mut rng = ChaCha20Rng::seed_from_u64(0xed_25519_b1_1d);

    for trial in 0..N_TRIALS {
        let k = deterministic_bytes(trial as u64, 0xa5);
        let peer_secret = deterministic_bytes(trial as u64, 0x5a);
        let u = x25519_base::<T>(&peer_secret);

        let unblinded = x25519::<T>(&k, &u);
        let blinded = x25519_blinded::<T, _>(&mut rng, &k, &u);

        assert_eq!(blinded, unblinded, "trial {trial} diverged");
    }
}

#[test]
fn blinded_matches_unblinded_x25519_base() {
    let mut rng = ChaCha20Rng::seed_from_u64(0xed_25519_ba_5e);

    for trial in 0..N_TRIALS {
        let k = deterministic_bytes(trial as u64, 0xc3);

        let unblinded = x25519_base::<T>(&k);
        let blinded = x25519_base_blinded::<T, _>(&mut rng, &k);

        assert_eq!(blinded, unblinded, "trial {trial} diverged");
    }
}

#[test]
fn blinded_with_zero_blinder_matches_unblinded() {
    // r = 0 → k' = k zero-extended; exercises the wider ladder loop's
    // leading-zero iterations.
    struct ZeroRng;
    impl rand_chacha::rand_core::RngCore for ZeroRng {
        fn next_u32(&mut self) -> u32 {
            0
        }
        fn next_u64(&mut self) -> u64 {
            0
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            dest.fill(0);
        }
    }
    impl rand_chacha::rand_core::CryptoRng for ZeroRng {}

    let k = deterministic_bytes(0x42, 0xff);
    let u = deterministic_bytes(0x42, 0x01);

    let unblinded = x25519::<T>(&k, &u);
    let blinded = x25519_blinded::<T, _>(&mut ZeroRng, &k, &u);

    assert_eq!(blinded, unblinded);
}

#[test]
fn blinded_with_max_blinder_matches_unblinded() {
    // r = u32::MAX exercises full-carry propagation through the
    // schoolbook multiply and the high end of the 544-bit ladder loop.
    struct MaxRng;
    impl rand_chacha::rand_core::RngCore for MaxRng {
        fn next_u32(&mut self) -> u32 {
            u32::MAX
        }
        fn next_u64(&mut self) -> u64 {
            u64::MAX
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            dest.fill(0xff);
        }
    }
    impl rand_chacha::rand_core::CryptoRng for MaxRng {}

    let k = deterministic_bytes(0xaa, 0x55);
    let peer_secret = deterministic_bytes(0xaa, 0xa5);
    let u = x25519_base::<T>(&peer_secret);

    let unblinded = x25519::<T>(&k, &u);
    let blinded = x25519_blinded::<T, _>(&mut MaxRng, &k, &u);

    assert_eq!(blinded, unblinded);
}

#[test]
fn blinded_produces_varying_intermediate_with_different_rng() {
    let mut rng_a = ChaCha20Rng::seed_from_u64(1);
    let mut rng_b = ChaCha20Rng::seed_from_u64(2);

    let k = deterministic_bytes(99, 0x77);
    let peer_secret = deterministic_bytes(99, 0x88);
    let u = x25519_base::<T>(&peer_secret);

    let unblinded = x25519::<T>(&k, &u);
    let from_a = x25519_blinded::<T, _>(&mut rng_a, &k, &u);
    let from_b = x25519_blinded::<T, _>(&mut rng_b, &k, &u);

    assert_eq!(from_a, unblinded);
    assert_eq!(from_b, unblinded);
}
