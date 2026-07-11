//! Compile-time enforcement of the CT typestate's negative guarantees
//! on `ed25519_heapless`'s own secret-carrying types. Each
//! `assert_not_impl_any!` fails the build if the listed trait is
//! implemented for the listed type, so a regression on the leak-surface
//! (adding `#[derive(Debug)]` on `SigningKey`, or an accidental
//! `impl Display`) is caught at `cargo test` rather than in the field.
//!
//! Mirrors the pattern from
//! `fixed-bigint-rs/tests/personality_negative_guarantees.rs` and
//! `modmath-rs/...`. See `notes/CT_VERIFY.md`.

#![cfg(all(
    feature = "fixed-bigint",
    any(feature = "sha512-hmac-sha512", feature = "sha512-sha2"),
))]

use core::fmt::{Debug, Display, LowerHex, UpperHex};
use ed25519_heapless::SigningKey;
use fixed_bigint::FixedUInt;
use static_assertions::assert_not_impl_any;

// SigningKey holds seed-derived clamped-scalar bytes and the nonce
// prefix — long-term secret material. Formatter traits would surface
// those bytes through `dbg!`, panic messages, and log lines; `Copy`
// would let accidental extra key frames land on the stack outside the
// `Zeroizing` wipe path. All four formatter traits plus `Copy` are
// deliberately absent — this test locks that in.
assert_not_impl_any!(
    SigningKey<FixedUInt<u32, 8, const_num_traits::Ct>>:
        Debug, Display, LowerHex, UpperHex, Copy
);

// Same assertion under the u8-limb carrier the `avr_demo` and
// size-constrained MCU builds use. `SigningKey<T>` is generic over T,
// so if a leak crept in via a `<T: Trait>`-conditioned blanket impl,
// re-instantiating at a second carrier surfaces it too.
assert_not_impl_any!(
    SigningKey<FixedUInt<u8, 32, const_num_traits::Ct>>:
        Debug, Display, LowerHex, UpperHex, Copy
);

// The Nct carrier isn't the intended `SigningKey` shape, but nothing
// in the type system forbids it. Assert the same leak-surface is
// missing regardless of personality — a `Debug` accidentally added
// under `where T: Debug` would fire here since Nct FixedUInt does
// implement Debug (unlike the redacted Ct variant).
assert_not_impl_any!(
    SigningKey<FixedUInt<u32, 8, const_num_traits::Nct>>:
        Debug, Display, LowerHex, UpperHex, Copy
);
