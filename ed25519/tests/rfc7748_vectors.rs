//! X25519 test vectors from RFC 7748.
//!
//! Requires the `fixed-bigint` feature.
//! Run with: cargo test -p ed25519_heapless --features fixed-bigint

#![cfg(feature = "fixed-bigint")]

use ed25519_heapless::{x25519, x25519_base};

// x25519 requires a Ct-typed backend (secret scalar). Pin P = Ct here.
type T = fixed_bigint::FixedUInt<u32, 16, const_num_traits::Ct>;

fn hex_to_array_32(hex: &str) -> [u8; 32] {
    assert_eq!(hex.len(), 64);
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

// ============================================================================
// RFC 7748 §5.2 - single-step test vectors
// ============================================================================

#[test]
fn rfc7748_5_2_vector_1() {
    let k = hex_to_array_32("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
    let u = hex_to_array_32("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
    let expected =
        hex_to_array_32("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
    assert_eq!(x25519::<T>(&k, &u).unwrap(), expected);
}

#[test]
fn rfc7748_5_2_vector_2() {
    let k = hex_to_array_32("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
    let u = hex_to_array_32("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
    let expected =
        hex_to_array_32("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");
    assert_eq!(x25519::<T>(&k, &u).unwrap(), expected);
}

// ============================================================================
// RFC 7748 §5.2 - iterated test vector (after 1 iteration)
//
// k = u = 0900...00; new k <- result(k,u); new u <- old k. After N steps,
// check k against the published vector.
// ============================================================================

#[test]
fn rfc7748_5_2_iter_1() {
    let mut k = [0u8; 32];
    k[0] = 9;
    let mut u = k;

    let result = x25519::<T>(&k, &u).unwrap();
    u = k;
    k = result;
    let _ = u;

    let expected =
        hex_to_array_32("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079");
    assert_eq!(k, expected);
}

#[test]
#[ignore = "1000 iterations is slow under fixed-bigint; run with --release --ignored"]
fn rfc7748_5_2_iter_1000() {
    let mut k = [0u8; 32];
    k[0] = 9;
    let mut u = k;

    for _ in 0..1000 {
        let result = x25519::<T>(&k, &u).unwrap();
        u = k;
        k = result;
    }

    let expected =
        hex_to_array_32("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51");
    assert_eq!(k, expected);
}

// ============================================================================
// RFC 7748 §6.1 - Diffie-Hellman example
// ============================================================================

#[test]
fn rfc7748_6_1_alice_public() {
    let alice_priv =
        hex_to_array_32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let expected_pub =
        hex_to_array_32("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    assert_eq!(x25519_base::<T>(&alice_priv).unwrap(), expected_pub);
}

#[test]
fn rfc7748_6_1_bob_public() {
    let bob_priv =
        hex_to_array_32("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    let expected_pub =
        hex_to_array_32("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    assert_eq!(x25519_base::<T>(&bob_priv).unwrap(), expected_pub);
}

#[test]
fn rfc7748_6_1_shared_secret() {
    let alice_priv =
        hex_to_array_32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let bob_priv =
        hex_to_array_32("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    let alice_pub =
        hex_to_array_32("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    let bob_pub =
        hex_to_array_32("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    let expected_shared =
        hex_to_array_32("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

    let ab = x25519::<T>(&alice_priv, &bob_pub).unwrap();
    let ba = x25519::<T>(&bob_priv, &alice_pub).unwrap();
    assert_eq!(ab, expected_shared);
    assert_eq!(ba, expected_shared);
}
