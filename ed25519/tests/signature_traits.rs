//! Integration tests for `signature` crate trait implementations.
//!
//! Run with: cargo test -p ed25519_heapless --features fixed-bigint

#![cfg(feature = "fixed-bigint")]

use ed25519_heapless::{SigningKey, VerifyingKey};
use signature::{Signer, Verifier};

type T = fixed_bigint::FixedUInt<u32, 16>;
// Sign requires the constant-time backend mode; verify is happy with
// either. Keep both aliases so each test exercises the realistic
// configuration for its operation.
type Tct = fixed_bigint::FixedUInt<u32, 16, const_num_traits::Ct>;

struct SigWrapper(Vec<u8>);

impl AsRef<[u8]> for SigWrapper {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn hex_to_array_32(hex: &str) -> [u8; 32] {
    let bytes = hex_to_bytes(hex);
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    arr
}

fn rfc_test1_public_key() -> [u8; 32] {
    hex_to_array_32("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
}

fn rfc_test1_signature() -> Vec<u8> {
    hex_to_bytes(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    )
}

#[test]
fn verifier_accepts_signature_wrapper_with_as_ref() {
    let verifying_key = VerifyingKey::<T>::from_bytes(rfc_test1_public_key());
    let signature = SigWrapper(rfc_test1_signature());

    assert!(verifying_key.verify(b"", &signature).is_ok());
}

#[test]
fn verifier_rejects_signature_with_invalid_length() {
    let verifying_key = VerifyingKey::<T>::from_bytes(rfc_test1_public_key());
    let signature = SigWrapper(vec![0u8; 63]);

    assert!(verifying_key.verify(b"", &signature).is_err());
}

#[test]
fn signer_matches_rfc8032_test1() {
    let seed = hex_to_array_32("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    let sk = SigningKey::<Tct>::from_seed(&seed).expect("from_seed");

    let sig: [u8; 64] = sk.try_sign(b"").expect("try_sign");
    let expected = rfc_test1_signature();
    assert_eq!(&sig[..], &expected[..]);
}

#[test]
fn signer_verifier_roundtrip() {
    // Distinct from the RFC fixed-vector tests: exercises the trait
    // surface end-to-end across several message shapes, including the
    // multi-block SHA-512 boundary.
    let seed = hex_to_array_32("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
    let sk = SigningKey::<Tct>::from_seed(&seed).expect("from_seed");
    let vk = VerifyingKey::<T>::from_bytes(sk.public_key());

    for msg in [
        b"".as_slice(),
        b"a".as_slice(),
        &[0xff; 32][..],
        &[0x55; 129][..],
    ] {
        let sig: [u8; 64] = sk.try_sign(msg).expect("try_sign");
        vk.verify(msg, &sig).expect("verify");
    }
}
