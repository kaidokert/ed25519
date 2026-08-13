//! X25519 KEM: DH-KEM round-trip, blinded/unblinded agreement, RFC 7748 vector.
//!
//! Requires the `fixed-bigint` feature.

#![cfg(feature = "fixed-bigint")]

use ed25519_heapless::x25519_kem::{
    DecapsulateError, DecapsulationKey, EncapsulationKey, X25519Kem,
};
use ed25519_heapless::{x25519, x25519_blinded};
use kem::{Ciphertext, Decapsulator, Encapsulate, Generate, KeyInit, TryDecapsulate, TryKeyInit};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

// 256-bit minimum Ct backend (one bit above the field prime).
type T = fixed_bigint::FixedUInt<u32, 8, const_num_traits::Ct>;

fn rng(seed: u8) -> ChaCha20Rng {
    ChaCha20Rng::from_seed([seed; 32])
}

fn hex32(hex: &str) -> [u8; 32] {
    assert_eq!(hex.len(), 64);
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

#[test]
fn dh_kem_round_trip() {
    let mut r = rng(1);
    let dk = DecapsulationKey::<T>::generate_from_rng(&mut r);
    let ek = dk.encapsulation_key().clone();

    let (ct, k_send) = ek.encapsulate_with_rng(&mut r);
    let k_recv = dk.try_decapsulate(&ct).expect("decapsulate");

    assert_eq!(k_send, k_recv, "encapsulate and decapsulate must agree");
    assert_ne!(
        k_send.as_slice(),
        [0u8; 32].as_slice(),
        "a healthy DH shared key is non-zero"
    );
}

#[test]
fn distinct_encapsulations_differ() {
    let mut r = rng(2);
    let dk = DecapsulationKey::<T>::generate_from_rng(&mut r);
    let ek = dk.encapsulation_key().clone();

    // Fresh ephemerals => distinct ciphertexts and shared keys, each still
    // round-tripping through the same decapsulation key.
    let (ct_a, k_a) = ek.encapsulate_with_rng(&mut r);
    let (ct_b, k_b) = ek.encapsulate_with_rng(&mut r);
    assert_ne!(ct_a, ct_b);
    assert_ne!(k_a, k_b);
    assert_eq!(k_a, dk.try_decapsulate(&ct_a).unwrap());
    assert_eq!(k_b, dk.try_decapsulate(&ct_b).unwrap());
}

#[test]
fn blinded_matches_unblinded_for_same_scalar() {
    // The KEM's blinded encapsulation relies on x25519_blinded producing the
    // same output as the plain ladder for a fixed scalar — blinding changes the
    // side-channel profile, not the result.
    let mut r = rng(3);
    let e = [0x11u8; 32];
    let u = hex32("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
    let unblinded = x25519::<T>(&e, &u).unwrap();
    let blinded = x25519_blinded::<T, _>(&mut r, &e, &u).unwrap();
    assert_eq!(unblinded, blinded);
}

#[test]
fn rfc7748_vector_through_decapsulate() {
    // RFC 7748 §5.2 vector 1: scalar · u = output. Decapsulation is sk · ct, so
    // loading sk = scalar and decapsulating ct = u reproduces the vector.
    let scalar = hex32("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
    let u = hex32("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
    let expected = hex32("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");

    let dk = <DecapsulationKey<T> as KeyInit>::new(&scalar.into());
    let ct: Ciphertext<X25519Kem<T>> = u.into();
    let ss = dk.try_decapsulate(&ct).expect("decapsulate");
    assert_eq!(ss.as_slice(), expected.as_slice());
}

#[test]
fn decapsulate_rejects_low_order_ciphertext() {
    // All-zero ciphertext is a low-order point → all-zero shared secret; must be
    // rejected rather than returned as a valid Ok.
    let mut r = rng(4);
    let dk = DecapsulationKey::<T>::generate_from_rng(&mut r);
    let ct: Ciphertext<X25519Kem<T>> = [0u8; 32].into();
    assert_eq!(
        dk.try_decapsulate(&ct),
        Err(DecapsulateError::LowOrderPoint)
    );
}

#[test]
fn try_key_init_rejects_low_order_and_accepts_valid() {
    // All-zero encapsulation key is low-order → rejected at decode.
    assert!(<EncapsulationKey<T> as TryKeyInit>::new(&[0u8; 32].into()).is_err());

    // A public key derived from a real secret is accepted.
    let mut r = rng(5);
    let dk = DecapsulationKey::<T>::generate_from_rng(&mut r);
    let ek_bytes = kem::KeyExport::to_bytes(dk.encapsulation_key());
    assert!(<EncapsulationKey<T> as TryKeyInit>::new(&ek_bytes).is_ok());
}
