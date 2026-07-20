//! Verify runs on a non-`Copy` heap carrier (`num-bigint`'s
//! `FixedWidthBigUint`) through the schoolbook (`Clone` / by-reference) verify
//! field — the verify-only exception to the `Copy` carrier rule. The carrier
//! satisfies neither `Copy` nor `subtle`, so it can never reach a CT path.

#![cfg(any(feature = "sha512-hmac-sha512", feature = "sha512-sha2"))]

use ed25519_heapless::{curve25519_schoolbook, verify_with_field};
use num_bigint::FixedWidthBigUint;

fn hex32(s: &str) -> [u8; 32] {
    assert_eq!(s.len(), 64, "expected 64 hex chars (32 bytes)");
    let mut o = [0u8; 32];
    for i in 0..32 {
        o[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    o
}
fn hex64(s: &str) -> [u8; 64] {
    assert_eq!(s.len(), 128, "expected 128 hex chars (64 bytes)");
    let mut o = [0u8; 64];
    for i in 0..64 {
        o[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    o
}

// RFC 8032 §7.1 Test 1 (empty message).
const PUBLIC: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const SIG: &str = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

#[test]
fn verify_valid_signature_on_heap_carrier() {
    let field = curve25519_schoolbook::<FixedWidthBigUint>().expect("schoolbook field");
    assert!(
        verify_with_field(&field, hex32(PUBLIC), b"", hex64(SIG)),
        "valid RFC 8032 signature must verify on the heap carrier"
    );
}

#[test]
fn verify_rejects_tampered_signature_on_heap_carrier() {
    let field = curve25519_schoolbook::<FixedWidthBigUint>().expect("schoolbook field");
    let mut sig = hex64(SIG);
    sig[0] ^= 0x01;
    assert!(
        !verify_with_field(&field, hex32(PUBLIC), b"", sig),
        "tampered signature must reject on the heap carrier"
    );
}
