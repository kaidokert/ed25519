//! Ed25519 test vectors from RFC 8032, Wycheproof, and negative tests
//!
//! These tests require the `fixed-bigint` feature.
//! Run with: cargo test -p ed25519_heapless --features fixed-bigint

#![cfg(feature = "fixed-bigint")]

type T = fixed_bigint::FixedUInt<u32, 16>;

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn hex_to_array_32(hex: &str) -> [u8; 32] {
    let bytes = hex_to_bytes(hex);
    assert_eq!(bytes.len(), 32);
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    arr
}

fn hex_to_array_64(hex: &str) -> [u8; 64] {
    let bytes = hex_to_bytes(hex);
    assert_eq!(bytes.len(), 64);
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&bytes);
    arr
}

// ============================================================================
// RFC 8032 Section 7.1 - Ed25519 test vectors
// ============================================================================

#[test]
fn rfc8032_test1_empty_message() {
    let pk = hex_to_array_32("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    let msg = b"";
    let sig = hex_to_array_64(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    );
    assert!(
        ed25519_heapless::verify::<T>(pk, msg, sig),
        "RFC 8032 TEST 1: empty message should ACCEPT"
    );
}

#[test]
fn rfc8032_test2_one_byte() {
    let pk = hex_to_array_32("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
    let msg = &hex_to_bytes("72");
    let sig = hex_to_array_64(
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    );
    assert!(
        ed25519_heapless::verify::<T>(pk, msg, sig),
        "RFC 8032 TEST 2: 1-byte message should ACCEPT"
    );
}

#[test]
fn rfc8032_test3_two_bytes() {
    let pk = hex_to_array_32("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025");
    let msg = &hex_to_bytes("af82");
    let sig = hex_to_array_64(
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    );
    assert!(
        ed25519_heapless::verify::<T>(pk, msg, sig),
        "RFC 8032 TEST 3: 2-byte message should ACCEPT"
    );
}

#[test]
fn rfc8032_test4_1023_bytes() {
    let pk = hex_to_array_32("278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e");
    let msg = &hex_to_bytes(
        "08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98\
         fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d8\
         79de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d\
         658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc\
         1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4fe\
         ba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e\
         06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbef\
         efd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7\
         aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed1\
         85ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2\
         d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24\
         554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f270\
         88d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc\
         2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b07\
         07e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128ba\
         b27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51a\
         ddd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429e\
         c96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb75\
         1fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c4\
         2f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8c\
         a61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34dff\
         7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08d\
         78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649d\
         e6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e48\
         8acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a32\
         ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e6\
         aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5fb\
         93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b50\
         d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef13\
         69546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380db\
         2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c0\
         618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0",
    );
    let sig = hex_to_array_64(
        "0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03",
    );
    assert!(
        ed25519_heapless::verify::<T>(pk, msg, sig),
        "RFC 8032 TEST 4: 1023-byte message should ACCEPT"
    );
}

#[test]
fn rfc8032_test5_sha_abc() {
    let pk = hex_to_array_32("ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf");
    let msg = &hex_to_bytes(
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
    );
    let sig = hex_to_array_64(
        "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
    );
    assert!(
        ed25519_heapless::verify::<T>(pk, msg, sig),
        "RFC 8032 TEST 5: SHA(abc) message should ACCEPT"
    );
}

// ============================================================================
// Negative test cases
// ============================================================================

// Use the RFC 8032 TEST 1 as the base for negative tests
const VALID_PK: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const VALID_SIG: &str = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

#[test]
fn negative_wrong_message() {
    let pk = hex_to_array_32(VALID_PK);
    let sig = hex_to_array_64(VALID_SIG);
    // Valid signature is for empty message; try with non-empty
    assert!(
        !ed25519_heapless::verify::<T>(pk, b"wrong", sig),
        "Wrong message should REJECT"
    );
}

#[test]
fn negative_flipped_sig_bit() {
    let pk = hex_to_array_32(VALID_PK);
    let mut sig = hex_to_array_64(VALID_SIG);
    sig[0] ^= 0x01;
    assert!(
        !ed25519_heapless::verify::<T>(pk, b"", sig),
        "Flipped signature bit should REJECT"
    );
}

#[test]
fn negative_flipped_pk_bit() {
    let mut pk = hex_to_array_32(VALID_PK);
    pk[0] ^= 0x01;
    let sig = hex_to_array_64(VALID_SIG);
    assert!(
        !ed25519_heapless::verify::<T>(pk, b"", sig),
        "Flipped public key bit should REJECT"
    );
}

#[test]
fn negative_all_zeros_signature() {
    let pk = hex_to_array_32(VALID_PK);
    let sig = [0u8; 64];
    assert!(
        !ed25519_heapless::verify::<T>(pk, b"", sig),
        "All-zeros signature should REJECT"
    );
}

#[test]
fn negative_all_zeros_pubkey() {
    let pk = [0u8; 32];
    let sig = hex_to_array_64(VALID_SIG);
    assert!(
        !ed25519_heapless::verify::<T>(pk, b"", sig),
        "All-zeros public key should REJECT"
    );
}

#[test]
fn negative_swapped_pk_sig_halves() {
    // Use valid test 2 pk with test 1 signature (mismatched key/sig)
    let pk = hex_to_array_32("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
    let sig = hex_to_array_64(VALID_SIG);
    assert!(
        !ed25519_heapless::verify::<T>(pk, b"", sig),
        "Wrong public key should REJECT"
    );
}

// ============================================================================
// Wycheproof Ed25519 test vectors (C2SP/wycheproof testvectors_v1/ed25519_test.json)
//
// Curated subset of ~40 vectors covering:
//   - Normal valid signatures
//   - Special values for R and S (zero, identity, group order)
//   - Signature malleability (S >= L, S with high bits)
//   - Invalid R encodings (flipped bits, non-canonical)
//   - Truncated / garbage-appended signatures
//   - Overflow / arithmetic regression vectors
// ============================================================================

struct WycheproofVector {
    tc_id: u32,
    comment: &'static str,
    pk: &'static str,
    msg: &'static str,
    sig: &'static str,
    valid: bool,
}

// ---------- VALID signatures ----------

const WYCHEPROOF_VALID: &[WycheproofVector] = &[
    // tcId 1: empty message
    WycheproofVector {
        tc_id: 1,
        comment: "empty message",
        pk: "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa",
        msg: "",
        sig: "d4fbdb52bfa726b44d1786a8c0d171c3e62ca83c9e5bbe63de0bb2483f8fd6cc1429ab72cafc41ab56af02ff8fcc43b99bfe4c7ae940f60f38ebaa9d311c4007",
        valid: true,
    },
    // tcId 3: "Test" message
    WycheproofVector {
        tc_id: 3,
        comment: "4-byte message (Test)",
        pk: "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa",
        msg: "54657374",
        sig: "7c38e026f29e14aabd059a0f2db8b0cd783040609a8be684db12f82a27774ab07a9155711ecfaf7f99f277bad0c6ae7e39d4eef676573336a5c51eb6f946b30d",
        valid: true,
    },
    // tcId 5: "123400" message
    WycheproofVector {
        tc_id: 5,
        comment: "6-byte message (123400)",
        pk: "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa",
        msg: "313233343030",
        sig: "657c1492402ab5ce03e2c3a7f0384d051b9cf3570f1207fc78c1bcc98c281c2bf0cf5b3a289976458a1be6277a5055545253b45b07dcc1abd96c8b989c00f301",
        valid: true,
    },
    // tcId 7: 64 bytes of 'a'
    WycheproofVector {
        tc_id: 7,
        comment: "64-byte message (all 0x61)",
        pk: "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa",
        msg: concat!(
            "6161616161616161616161616161616161616161616161616161616161616161",
            "616161616161616161616161616161616161616161616161616161616161616161",
        ),
        sig: "879350045543bc14ed2c08939b68c30d22251d83e018cacbaf0c9d7a48db577e80bdf76ce99e5926762bc13b7b3483260a5ef63d07e34b58eb9c14621ac92f00",
        valid: true,
    },
    // tcId 9: 16 bytes of 0xff
    WycheproofVector {
        tc_id: 9,
        comment: "16-byte message (all 0xff)",
        pk: "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa",
        msg: "ffffffffffffffffffffffffffffffff",
        sig: "5dbd7360e55aa38e855d6ad48c34bd35b7871628508906861a7c4776765ed7d1e13d910faabd689ec8618b78295c8ab8f0e19c8b4b43eb8685778499e943ae04",
        valid: true,
    },
    // tcId 70: RFC draft test 1 (empty msg, different key)
    WycheproofVector {
        tc_id: 70,
        comment: "draft-josefsson-eddsa-ed25519-02: Test 1",
        pk: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        msg: "",
        sig: "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        valid: true,
    },
    // tcId 71: RFC draft test 2 (1-byte msg 0x72)
    WycheproofVector {
        tc_id: 71,
        comment: "draft-josefsson-eddsa-ed25519-02: Test 2",
        pk: "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        msg: "72",
        sig: "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        valid: true,
    },
    // tcId 74: S just under the bound
    WycheproofVector {
        tc_id: 74,
        comment: "S just under the bound",
        pk: "100fdf47fb94f1536a4f7c3fda27383fa03375a8f527c537e6f1703c47f94f86",
        msg: "124e583f8b8eca58bb29c271b41d36986bbc45541f8e51f9cb0133eca447601e",
        sig: "dac119d6ca87fc59ae611c157048f4d4fc932a149dbe20ec6effd1436abf83ea05c7df0fef06147241259113909bc71bd3c53ba4464ffcad3c0968f2ffffff0f",
        valid: true,
    },
    // tcId 119: overflow in signature generation
    WycheproofVector {
        tc_id: 119,
        comment: "overflow in signature generation",
        pk: "037b55b427dc8daa0f80fcebaf0846902309f8a6cf18b465c0ce9b6539629ac8",
        msg: "01234567",
        sig: "c964e100033ce8888b23466677da4f4aea29923f642ae508f9d0888d788150636ab9b2c3765e91bbb05153801114d9e52dc700df377212222bb766be4b8c020d",
        valid: true,
    },
];

// ---------- INVALID signatures ----------

const WYCHEPROOF_INVALID: &[WycheproofVector] = &[
    // --- Special values for R and S ---

    // tcId 10: R=0, S=0
    WycheproofVector {
        tc_id: 10,
        comment: "R=0 S=0",
        pk: "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa",
        msg: "3f",
        sig: "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        valid: false,
    },
    // tcId 11: R=0, S=1
    WycheproofVector {
        tc_id: 11,
        comment: "R=0 S=1",
        pk: "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa",
        msg: "3f",
        sig: "00000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000",
        valid: false,
    },
    // tcId 13: R=0, S=L (group order, exactly)
    WycheproofVector {
        tc_id: 13,
        comment: "R=0 S=L (group order)",
        pk: "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa",
        msg: "3f",
        sig: "0000000000000000000000000000000000000000000000000000000000000000edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
        valid: false,
    },
    // tcId 14: R=0, S=p (field prime 2^255-19)
    WycheproofVector {
        tc_id: 14,
        comment: "R=0 S=2^255-19 (field prime)",
        pk: "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa",
        msg: "3f",
        sig: "0000000000000000000000000000000000000000000000000000000000000000edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        valid: false,
    },
    // tcId 15: R=1 (small-order point), S=0
    WycheproofVector {
        tc_id: 15,
        comment: "R=1 (identity point) S=0",
        pk: "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa",
        msg: "3f",
        sig: "01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        valid: false,
    },
    // tcId 18: R=1 (identity), S=L
    WycheproofVector {
        tc_id: 18,
        comment: "R=1 (identity) S=L (group order)",
        pk: "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa",
        msg: "3f",
        sig: "0100000000000000000000000000000000000000000000000000000000000000edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
        valid: false,
    },
    // tcId 24: R=p (non-canonical), S=0
    WycheproofVector {
        tc_id: 24,
        comment: "R=2^255-19 (non-canonical) S=0",
        pk: "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa",
        msg: "3f",
        sig: "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000000000000000000000000000000000000",
        valid: false,
    },
    // tcId 27: R=p, S=L
    WycheproofVector {
        tc_id: 27,
        comment: "R=2^255-19 S=L (both non-canonical)",
        pk: "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa",
        msg: "3f",
        sig: "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7fedd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
        valid: false,
    },
    // tcId 28: R=p, S=p
    WycheproofVector {
        tc_id: 28,
        comment: "R=2^255-19 S=2^255-19",
        pk: "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa",
        msg: "3f",
        sig: "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7fedffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        valid: false,
    },
    // --- Signature malleability (S >= L) ---

    // tcId 62: S has L added (s' = s + L, wraps scalar range)
    WycheproofVector {
        tc_id: 62,
        comment: "S + L (signature malleability)",
        pk: "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa",
        msg: "54657374",
        sig: "7c38e026f29e14aabd059a0f2db8b0cd783040609a8be684db12f82a27774ab067654bce3832c2d76f8f6f5dafc08d9339d4eef676573336a5c51eb6f946b31d",
        valid: false,
    },
    // tcId 63: S + 2*L
    WycheproofVector {
        tc_id: 63,
        comment: "S + 2L (signature malleability)",
        pk: "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa",
        msg: "54657374",
        sig: "7c38e026f29e14aabd059a0f2db8b0cd783040609a8be684db12f82a27774ab05439412b5395d42f462c67008eba6ca839d4eef676573336a5c51eb6f946b32d",
        valid: false,
    },
    // tcId 66: S with bit 255 set
    WycheproofVector {
        tc_id: 66,
        comment: "S with bit 255 set (malleability)",
        pk: "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa",
        msg: "54657374",
        sig: "7c38e026f29e14aabd059a0f2db8b0cd783040609a8be684db12f82a27774ab07a9155711ecfaf7f99f277bad0c6ae7e39d4eef676573336a5c51eb6f946b38d",
        valid: false,
    },
    // tcId 67: S with bit 256 set (high bit in S byte 31)
    WycheproofVector {
        tc_id: 67,
        comment: "S with bits 256+255 set (malleability)",
        pk: "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa",
        msg: "54657374",
        sig: "7c38e026f29e14aabd059a0f2db8b0cd783040609a8be684db12f82a27774ab07a9155711ecfaf7f99f277bad0c6ae7e39d4eef676573336a5c51eb6f946b34d",
        valid: false,
    },
    // tcId 75: S just above the bound
    WycheproofVector {
        tc_id: 75,
        comment: "S just above the bound (S >= L)",
        pk: "100fdf47fb94f1536a4f7c3fda27383fa03375a8f527c537e6f1703c47f94f86",
        msg: "6a0bc2b0057cedfc0fa2e3f7f7d39279b30f454a69dfd1117c758d86b19d85e0",
        sig: "0971f86d2c9c78582524a103cb9cf949522ae528f8054dc20107d999be673ff4e25ebf2f2928766b1248bec6e91697775f8446639ede46ad4df4053000000010",
        valid: false,
    },
    // --- Invalid R encodings (flipped bits) ---

    // tcId 42: modified bit 0 in R
    WycheproofVector {
        tc_id: 42,
        comment: "modified bit 0 in R",
        pk: "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa",
        msg: "313233343030",
        sig: "647c1492402ab5ce03e2c3a7f0384d051b9cf3570f1207fc78c1bcc98c281c2b1d125e5538f38afbcc1c84e489521083041d24bc6240767029da063271a1ff0c",
        valid: false,
    },
    // tcId 45: modified bit 7 in R
    WycheproofVector {
        tc_id: 45,
        comment: "modified bit 7 in R",
        pk: "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa",
        msg: "313233343030",
        sig: "e57c1492402ab5ce03e2c3a7f0384d051b9cf3570f1207fc78c1bcc98c281c2bbb3eb51cd98dddb235a5f46f2bded6af184a58d09cce928bda43f41d69118a03",
        valid: false,
    },
    // tcId 55: modified bit 248 in R (high byte)
    WycheproofVector {
        tc_id: 55,
        comment: "modified bit 248 in R (high byte flip)",
        pk: "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa",
        msg: "313233343030",
        sig: "657c1492402ab5ce03e2c3a7f0384d051b9cf3570f1207fc78c1bcc98c281c2a63950c85cd6dc96364e768de50ff7732b538f8a0b1615d799190ab600849230e",
        valid: false,
    },
    // tcId 58: modified bit 255 in R (sign bit)
    WycheproofVector {
        tc_id: 58,
        comment: "modified bit 255 in R (sign bit flip)",
        pk: "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa",
        msg: "313233343030",
        sig: "657c1492402ab5ce03e2c3a7f0384d051b9cf3570f1207fc78c1bcc98c281cab227aedf259f910f0f3a759a335062665217925d019173b88917eae294f75d40f",
        valid: false,
    },
    // --- R=0 and R=0xff..ff (identity / invalid point) ---

    // tcId 59: R==0 (the zero point encoding)
    WycheproofVector {
        tc_id: 59,
        comment: "R==0 (zero encoding)",
        pk: "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa",
        msg: "313233343030",
        sig: "0000000000000000000000000000000000000000000000000000000000000000e0b8e7770d51c7a36375d006c5bffd6af43ff54aaf47e4330dc118c71d61ec02",
        valid: false,
    },
    // tcId 60: R=0xff..ff (all bits set, invalid point)
    WycheproofVector {
        tc_id: 60,
        comment: "R=0xff..ff (invalid point)",
        pk: "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa",
        msg: "313233343030",
        sig: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff463a1908382e7eb7693acef9884f7cf931a215e0791876be22c631a59881fd0e",
        valid: false,
    },
    // tcId 61: all bits flipped in R
    WycheproofVector {
        tc_id: 61,
        comment: "all bits flipped in R",
        pk: "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa",
        msg: "313233343030",
        sig: "9a83eb6dbfd54a31fc1d3c580fc7b2fae4630ca8f0edf803873e433673d7e3d40e94254586cb6188c5386c3febed477cb9a6cb29e3979adc4cb27cf5278fb70a",
        valid: false,
    },
    // --- Truncated / garbage signatures ---

    // tcId 33: signature too long (appended 2020)
    WycheproofVector {
        tc_id: 33,
        comment: "signature too long (appended garbage)",
        pk: "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa",
        msg: "54657374",
        // 66 bytes - first 64 are the valid sig from tcId 3, then "2020"
        sig: "7c38e026f29e14aabd059a0f2db8b0cd783040609a8be684db12f82a27774ab07a9155711ecfaf7f99f277bad0c6ae7e39d4eef676573336a5c51eb6f946b30d2020",
        valid: false,
    },
    // tcId 37: appending 0 byte to signature
    WycheproofVector {
        tc_id: 37,
        comment: "appending 0x00 to valid signature",
        pk: "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa",
        msg: "54657374",
        sig: "7c38e026f29e14aabd059a0f2db8b0cd783040609a8be684db12f82a27774ab07a9155711ecfaf7f99f277bad0c6ae7e39d4eef676573336a5c51eb6f946b30d00",
        valid: false,
    },
    // --- Arithmetic regression / overflow ---

    // tcId 126: regression for arithmetic error
    WycheproofVector {
        tc_id: 126,
        comment: "regression: arithmetic overflow (TinkOverflow)",
        pk: "0717d75ce27ea181ed5a30e6456c649b5cf453a6b4c12cd3f9fd16b31e0c25cd",
        msg: "26d5f0631f49106db58c4cfc903691134811b33c",
        sig: "9588e02bc815649d359ce710cdc69814556dd8c8bab1c468f40a49ebefb7f0de7ed49725edfd1b708fa1bad277c35d6c1b9c5ec25990997645780f9203d7dd08",
        valid: true,
    },
    // tcId 130: regression for arithmetic error
    WycheproofVector {
        tc_id: 130,
        comment: "regression: arithmetic overflow (TinkOverflow)",
        pk: "38ead304624abebf3e2b31e20e5629531e3fc659008887c9106f5e55adbbc62a",
        msg: "ae03da6997e40cea67935020152d3a9a365cc055",
        sig: "068eafdc2f36b97f9bae7fbda88b530d16b0e35054d3a351e3a4c914b22854c711505e49682e1a447e10a69e3b04d0759c859897b64f71137acf355b63faf100",
        valid: true,
    },
    // tcId 135: regression for arithmetic error
    WycheproofVector {
        tc_id: 135,
        comment: "regression: arithmetic overflow (TinkOverflow)",
        pk: "127d37e406e0d83e4b55a09e21e8f50fb88af47e4a43f018cdebffc1948757f0",
        msg: "e1ce107971534bc46a42ac609a1a37b4ca65791d",
        sig: "00c11e76b5866b7c37528b0670188c1a0473fb93c33b72ae604a8865a7d6e094ff722e8ede3cb18389685ff3c4086c29006047466f81e71a329711e0b9294709",
        valid: true,
    },
];

#[test]
fn wycheproof_valid_signatures() {
    for v in WYCHEPROOF_VALID {
        let pk = hex_to_array_32(v.pk);
        let msg = hex_to_bytes(v.msg);
        let sig = hex_to_array_64(v.sig);
        assert!(
            ed25519_heapless::verify::<T>(pk, &msg, sig),
            "Wycheproof tcId {}: {} — expected VALID",
            v.tc_id,
            v.comment
        );
    }
}

#[test]
fn wycheproof_invalid_signatures() {
    for v in WYCHEPROOF_INVALID {
        if v.valid {
            // Some "invalid category" vectors are actually valid (TinkOverflow regressions)
            let pk = hex_to_array_32(v.pk);
            let msg = hex_to_bytes(v.msg);
            let sig = hex_to_array_64(v.sig);
            assert!(
                ed25519_heapless::verify::<T>(pk, &msg, sig),
                "Wycheproof tcId {}: {} — expected VALID",
                v.tc_id,
                v.comment
            );
            continue;
        }
        let sig_bytes = hex_to_bytes(v.sig);
        if sig_bytes.len() != 64 {
            // Truncated or garbage-appended sigs can't reach crypto: our verify()
            // takes [u8; 64], so the length check is enforced at the type level.
            continue;
        }
        let pk = hex_to_array_32(v.pk);
        let msg = hex_to_bytes(v.msg);
        let sig = hex_to_array_64(v.sig);
        assert!(
            !ed25519_heapless::verify::<T>(pk, &msg, sig),
            "Wycheproof tcId {}: {} — expected INVALID",
            v.tc_id,
            v.comment
        );
    }
}
