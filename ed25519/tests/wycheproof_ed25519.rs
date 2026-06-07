//! Wycheproof Ed25519 verification conformance test.
//!
//! Source: <https://github.com/randombit/wycheproof-rs>. Dev-dep only.
//!
//! We use the non-CT backend for verify (public-input operation, no
//! secret-handling) — `FixedUInt<u32, 16, Nct>`. The `verify` entry
//! point in `strict.rs` returns `bool`, so the test logic is:
//!
//! * `TestResult::Valid` → must return `true`.
//! * `TestResult::Invalid` → must return `false`.
//! * `TestResult::Acceptable` → either is OK; informational only.
//!
//! Vectors with the wrong signature length (Wycheproof carries truncated
//! and oversize signatures, flagged TruncatedSignature etc.) can't be
//! fed to our 64-byte-array API. Those are treated as "rejected before
//! verify" which matches the expected `Invalid` outcome — counted as
//! `rejected_at_parse` rather than skipped.

#![cfg(all(feature = "fixed-bigint", feature = "sha512-hmac-sha512"))]

use ed25519_heapless::verify;
use fixed_bigint::{FixedUInt, Nct};
use wycheproof::TestResult;

type T = FixedUInt<u32, 16, Nct>;

#[test]
fn wycheproof_ed25519() {
    let set = wycheproof::eddsa::TestSet::load(wycheproof::eddsa::TestName::Ed25519)
        .expect("wycheproof Ed25519 corpus failed to load");

    let mut ran = 0usize;
    let mut rejected_at_parse = 0usize;
    let mut failures = 0usize;

    for group in &set.test_groups {
        let public_key: [u8; 32] = match group.key.pk.as_ref().try_into() {
            Ok(b) => b,
            Err(_) => {
                eprintln!("skipping group: public key length != 32");
                continue;
            }
        };

        for tc in &group.tests {
            let msg = tc.msg.as_ref();

            // Wycheproof Ed25519 signatures are mostly 64 bytes; the
            // truncated/garbage variants are flagged Invalid. If we
            // can't parse the length, we know we'd reject — verify the
            // expectation says the same.
            let sig: [u8; 64] = match tc.sig.as_ref().try_into() {
                Ok(b) => b,
                Err(_) => {
                    rejected_at_parse += 1;
                    if !tc.result.must_fail() {
                        eprintln!(
                            "tcId {} ({:?}) flags={:?}: rejected at parse but Wycheproof says {:?}",
                            tc.tc_id, tc.comment, tc.flags, tc.result
                        );
                        failures += 1;
                    }
                    continue;
                }
            };

            let ok = verify::<T>(public_key, msg, sig);
            ran += 1;

            let outcome_matches = match tc.result {
                TestResult::Valid => ok,
                TestResult::Invalid => !ok,
                TestResult::Acceptable => true,
            };

            if !outcome_matches {
                eprintln!(
                    "tcId {} ({:?}) flags={:?} result={:?}: verify returned {}",
                    tc.tc_id, tc.comment, tc.flags, tc.result, ok
                );
                failures += 1;
            }
        }
    }

    eprintln!(
        "wycheproof Ed25519: ran={ran} rejected_at_parse={rejected_at_parse} failed={failures}"
    );
    assert!(ran > 0, "no Wycheproof Ed25519 vectors executed");
    assert_eq!(
        failures, 0,
        "{failures} Wycheproof Ed25519 vectors mismatched"
    );
}
