//! Wycheproof X25519 corpus run through the blinded path. With the
//! universal `8·ℓ·ℓ'` blinder, blinded must match unblinded for every
//! accepted u-coordinate — curve or twist.

#![cfg(feature = "fixed-bigint")]

use const_num_traits::Ct;
use ed25519_heapless::hazmat::{x25519, x25519_blinded};
use fixed_bigint::FixedUInt;
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;

type T = FixedUInt<u32, 16, Ct>;

#[test]
fn wycheproof_x25519_blinded_matches_unblinded() {
    let set = wycheproof::xdh::TestSet::load(wycheproof::xdh::TestName::X25519)
        .expect("wycheproof X25519 corpus failed to load");

    let mut rng = ChaCha20Rng::seed_from_u64(0xb1_1d_ed_25519);
    let mut ran = 0usize;
    let mut failures = 0usize;

    for group in &set.test_groups {
        for tc in &group.tests {
            let priv_bytes: [u8; 32] = match tc.private_key.as_ref().try_into() {
                Ok(b) => b,
                Err(_) => continue,
            };
            let pub_bytes: [u8; 32] = match tc.public_key.as_ref().try_into() {
                Ok(b) => b,
                Err(_) => continue,
            };

            let unblinded = x25519::<T>(&priv_bytes, &pub_bytes).unwrap();
            let blinded = x25519_blinded::<T, _>(&mut rng, &priv_bytes, &pub_bytes).unwrap();

            ran += 1;
            if blinded != unblinded {
                eprintln!(
                    "tcId {} ({:?}) flags={:?}: blinded {:02x?} vs unblinded {:02x?}",
                    tc.tc_id, tc.comment, tc.flags, blinded, unblinded
                );
                failures += 1;
            }
        }
    }

    eprintln!("wycheproof X25519 blinded: ran={ran} failed={failures}");
    assert_eq!(failures, 0);
}
