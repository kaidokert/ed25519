//! Wycheproof X25519 conformance test (Project Wycheproof v1 corpus).
//!
//! Source: <https://github.com/randombit/wycheproof-rs> — vendors the
//! upstream JSON vectors as a Rust crate (dev-dep only).
//!
//! Coverage matters for X25519 because RFC 7748 §5 says implementations
//! are *not required* to reject low-order points or twist points — but if
//! they accept them, the output of the scalar multiplication must equal
//! the value Wycheproof specifies. Our `x25519::x25519` always computes
//! (no input rejection), so we always compare against `shared_secret`.

#![cfg(feature = "fixed-bigint")]

use const_num_traits::Ct;
use ed25519_heapless::hazmat::x25519;
use fixed_bigint::FixedUInt;

type T = FixedUInt<u32, 16, Ct>;

#[test]
fn wycheproof_x25519() {
    let set = wycheproof::xdh::TestSet::load(wycheproof::xdh::TestName::X25519)
        .expect("wycheproof X25519 corpus failed to load");

    let mut ran = 0usize;
    let mut skipped = 0usize;
    let mut failures = 0usize;

    for group in &set.test_groups {
        for tc in &group.tests {
            // X25519 takes a fixed 32-byte private scalar and 32-byte
            // peer u-coordinate. Wycheproof carries some malformed-length
            // public keys (flagged PublicKeyTooLong) which we can't even
            // feed to our API — count those as skipped, not failed.
            let priv_bytes: [u8; 32] = match tc.private_key.as_ref().try_into() {
                Ok(b) => b,
                Err(_) => {
                    // Length mismatch on a Valid / Acceptable case is a
                    // silent test gap, not a legitimate skip.
                    if !tc.result.must_fail() {
                        eprintln!(
                            "tcId {} ({:?}) flags={:?}: private key rejected at parse but Wycheproof says {:?}",
                            tc.tc_id, tc.comment, tc.flags, tc.result
                        );
                        failures += 1;
                    }
                    skipped += 1;
                    continue;
                }
            };
            let pub_bytes: [u8; 32] = match tc.public_key.as_ref().try_into() {
                Ok(b) => b,
                Err(_) => {
                    if !tc.result.must_fail() {
                        eprintln!(
                            "tcId {} ({:?}) flags={:?}: public key rejected at parse but Wycheproof says {:?}",
                            tc.tc_id, tc.comment, tc.flags, tc.result
                        );
                        failures += 1;
                    }
                    skipped += 1;
                    continue;
                }
            };
            let expected: [u8; 32] = tc
                .shared_secret
                .as_ref()
                .try_into()
                .expect("Wycheproof shared_secret should always be 32 bytes for X25519");

            let got = x25519::<T>(&priv_bytes, &pub_bytes).unwrap();
            ran += 1;
            if got != expected {
                eprintln!(
                    "tcId {} ({:?}) flags={:?} result={:?}: expected {:02x?} got {:02x?}",
                    tc.tc_id, tc.comment, tc.flags, tc.result, expected, got
                );
                failures += 1;
            }
        }
    }

    eprintln!("wycheproof X25519: ran={ran} skipped={skipped} failed={failures}");
    assert!(ran > 0, "no Wycheproof X25519 vectors executed");
    assert_eq!(
        failures, 0,
        "{failures} Wycheproof X25519 vectors mismatched"
    );
}
