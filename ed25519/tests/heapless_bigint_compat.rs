//! Compile + smoke test with fixed-bigint 0.6's `HeaplessBigInt` as
//! the backend `T`. The runtime-length carrier is a fresh type on
//! the alpha ecosystem — this test proves it satisfies every trait
//! bound ed25519_heapless demands on both the CT (sign / x25519)
//! and NCT (verify) sides, and that the entry points at least
//! COMPILE and don't panic on well-formed inputs.
//!
//! Runtime semantic equivalence with the `FixedUInt` backend is
//! NOT holding on this alpha stack as of `v0.6.0-alpha.14`
//! (fixed-bigint) + `v0.6.0-alpha.cios.2` (modmath). Symptoms:
//!
//! - `sign_verify_roundtrip_over_heapless_bigint`: sign produces a
//!   signature that `verify::<HeaplessBigInt>` rejects.
//! - `public_key_matches_fixeduint_backend`: same seed derives
//!   DIFFERENT public keys under `HeaplessBigInt<u32, 8, Ct>` vs
//!   `FixedUInt<u32, 8, Ct>`.
//! - `verify_matches_fixeduint_backend`: `verify::<HeaplessBigInt>`
//!   rejects a signature the `FixedUInt`-instantiated verify
//!   accepts.
//!
//! ed25519's source didn't change on this branch — the runtime
//! disagreement is somewhere in the modmath ↔ HeaplessBigInt
//! binding, likely around how `len` is threaded through Montgomery
//! multiplication when the carrier's used-limb count is runtime-set
//! rather than always-CAP. Tests are kept as expected-fail so the
//! signal remains visible while upstream integration matures; flip
//! them back to `#[test]` (they already are) — no `#[ignore]` — as
//! soon as the alpha stack fixes this.

#![cfg(all(
    feature = "fixed-bigint",
    any(feature = "sha512-hmac-sha512", feature = "sha512-sha2"),
))]

use const_num_traits::{Ct, Nct};
use ed25519_heapless::{SigningKey, sign, verify, x25519, x25519_base};
use fixed_bigint::{FixedUInt, HeaplessBigInt};

// Curve25519-shaped: 8 × u32 = 256 bits, mirrors the FixedUInt<u32, 8, _>
// path the existing test suite exercises so results are directly comparable.
type TCt = HeaplessBigInt<u32, 8, Ct>;
type TNct = HeaplessBigInt<u32, 8, Nct>;
type FCt = FixedUInt<u32, 8, Ct>;
type FNct = FixedUInt<u32, 8, Nct>;

#[test]
fn public_key_matches_fixeduint_backend() {
    let seed = [7u8; 32];
    let pk_hb = SigningKey::<TCt>::from_seed(&seed)
        .expect("from_seed heapless")
        .public_key();
    let pk_fb = SigningKey::<FCt>::from_seed(&seed)
        .expect("from_seed fixeduint")
        .public_key();
    assert_eq!(
        pk_hb, pk_fb,
        "sign-side pubkey disagreement between backends"
    );
}

#[test]
fn verify_matches_fixeduint_backend() {
    let seed = [7u8; 32];
    let sk = SigningKey::<FCt>::from_seed(&seed).expect("from_seed");
    let pk = sk.public_key();
    let msg = b"hello, HeaplessBigInt";
    let sig = sign(&sk, msg).expect("sign");
    // Same signature, verified through each backend.
    let ok_fb = verify::<FNct>(pk, msg, sig);
    let ok_hb = verify::<TNct>(pk, msg, sig);
    assert!(ok_fb, "verify::<FixedUInt> rejected a valid signature");
    assert!(ok_hb, "verify::<HeaplessBigInt> rejected a valid signature");
}

#[test]
fn sign_verify_roundtrip_over_heapless_bigint() {
    let seed = [7u8; 32];
    let sk = SigningKey::<TCt>::from_seed(&seed).expect("from_seed");
    let pk = sk.public_key();
    let msg = b"hello, HeaplessBigInt";
    let sig = sign(&sk, msg).expect("sign");
    assert!(verify::<TNct>(pk, msg, sig));
}

#[test]
fn x25519_completes_over_heapless_bigint() {
    let k = [3u8; 32];
    let u = [5u8; 32];
    let _ = x25519::<TCt>(&k, &u);
    let _ = x25519_base::<TCt>(&k);
}
