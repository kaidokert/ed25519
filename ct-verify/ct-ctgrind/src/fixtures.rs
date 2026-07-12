//! Taint wrappers for ed25519_heapless's secret-touching entry
//! points, plus deliberately-secret-branchy negative controls.
//!
//! Positive fixtures mark seeds / secret scalars `MAKE_MEM_UNDEFINED`
//! before calling ed25519_heapless's public API directly. Any
//! secret-dependent branch or memory index anywhere between the
//! tainted input and the observed output — including inside inlined
//! upstream primitives — trips a Valgrind memcheck error.
//!
//! Negative controls do a naive secret-dep operation (branch, index,
//! equality) that Valgrind MUST flag. If it doesn't, the taint
//! plumbing is broken.

use crate::macros::{ctgrind_fixture, taint_val, untaint_val};
use const_num_traits::Ct;
use core::hint::black_box;
use ed25519_heapless::{SigningKey, sign, x25519, x25519_base};
use fixed_bigint::FixedUInt;

type T = FixedUInt<u32, 8, Ct>;

// ============================================================================
// Positive fixtures — secret input tainted, output observed clean.
// ============================================================================

// `black_box` on each zero-init input before `taint_val` is
// load-bearing: without it the fat-LTO release build sees the
// concrete zero value, const-folds `SigningKey::from_seed` /
// `x25519` at compile time, and the runtime never actually reads the
// tainted memory — a false pass. Same story for the negative
// controls below.

ctgrind_fixture!(ct_fix__signing_key_from_seed, {
    let seed = black_box([0u8; 32]);
    taint_val(&seed);
    if let Ok(sk) = SigningKey::<T>::from_seed(&seed) {
        let pk = sk.public_key();
        // The public key is public — untaint before observing so a
        // stray propagated V-bit doesn't false-flag.
        untaint_val(&pk);
        let _ = black_box(pk);
    }
});

ctgrind_fixture!(ct_fix__sign, {
    let seed = black_box([0u8; 32]);
    // Fixed public message — length + contents are public. Not tainted.
    let msg: &[u8] = b"ct-ctgrind message";
    taint_val(&seed);
    if let Ok(sk) = SigningKey::<T>::from_seed(&seed) {
        if let Ok(sig) = sign(&sk, msg) {
            untaint_val(&sig);
            let _ = black_box(sig);
        }
    }
});

ctgrind_fixture!(ct_fix__x25519, {
    let k = black_box([0u8; 32]);
    // u_in is the counterparty coordinate — public per RFC 7748.
    let u_in = black_box([0u8; 32]);
    taint_val(&k);
    let out = x25519::<T>(&k, &u_in);
    untaint_val(&out);
    let _ = black_box(out);
});

ctgrind_fixture!(ct_fix__x25519_base, {
    let k = black_box([0u8; 32]);
    taint_val(&k);
    let out = x25519_base::<T>(&k);
    untaint_val(&out);
    let _ = black_box(out);
});

// ============================================================================
// Negative controls — MUST trip Valgrind memcheck errors.
// ============================================================================

// Naked secret-dep branch. Reads the low bit of a tainted byte and
// takes different code paths on it.
ctgrind_fixture!(nct_fix__neg__branch_on_secret, {
    let secret = black_box([0u8; 32]);
    taint_val(&secret);
    let observed = if secret[0] & 1 == 0 {
        black_box(1u8)
    } else {
        black_box(2u8)
    };
    let _ = black_box(observed);
});

// Secret-index memory access. Uses a tainted byte as a table index.
ctgrind_fixture!(nct_fix__neg__index_by_secret, {
    let secret = black_box([0u8; 32]);
    let table = black_box([0u8; 256]);
    taint_val(&secret);
    let idx = secret[0] as usize;
    let observed = table[idx];
    let _ = black_box(observed);
});

// Secret-value equality test. `==` on a tainted operand.
ctgrind_fixture!(nct_fix__neg__equality_on_secret, {
    let secret = black_box([0u8; 32]);
    taint_val(&secret);
    let observed = if secret[0] == 42 {
        black_box(1u8)
    } else {
        black_box(2u8)
    };
    let _ = black_box(observed);
});
