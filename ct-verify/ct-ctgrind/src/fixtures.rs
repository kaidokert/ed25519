//! Taint wrappers for ed25519_heapless's secret-touching entry
//! points, plus deliberately-secret-branchy negative controls.
//!
//! Positive fixtures mark seeds / secret scalars `MAKE_MEM_UNDEFINED`
//! before calling ed25519_heapless's public API directly. Any
//! secret-dependent branch or memory index anywhere between the
//! tainted input and the observed output — including inside inlined
//! upstream primitives — trips a Valgrind memcheck error.
//!
//! Three carriers exercised to catch codegen-shape differences:
//!
//! - `FixedUInt<u32, 8, Ct>` — 32-bit word carrier, minimum size
//!   (256 bits, exactly one bit above the field prime).
//! - `FixedUInt<u32, 16, Ct>` — 32-bit word carrier at the shape
//!   the `cortex_m_demo` and `riscv_demo` examples deploy (512
//!   bits; matches the SHA-512 hash width without an intermediate
//!   truncation).
//! - `FixedUInt<u8, 32, Ct>` — 8-bit word carrier (`avr_demo` and
//!   the size-constrained cortex_m u8 example).
//!
//! "Codegen is width-generic" is an argument, not a verification —
//! the u8-limb and 16-limb monomorphizations have different loop
//! shapes and memory layouts than the 8-limb one, so a leak that
//! surfaces only in one wouldn't be caught by fixturing another.
//!
//! Negative controls do a naive secret-dep operation (branch, index,
//! equality) that Valgrind MUST flag. If it doesn't, the taint
//! plumbing is broken.

use const_num_traits::Ct;
use core::hint::black_box;
use ed25519_heapless::{SigningKey, sign, x25519, x25519_base};
use fixed_bigint::FixedUInt;
use krabi_caliper::ctgrind_fixture;
use krabi_caliper::host::ctgrind::{taint_val, untaint_val};

type T32x8 = FixedUInt<u32, 8, Ct>;
type T32x16 = FixedUInt<u32, 16, Ct>;
type T8x32 = FixedUInt<u8, 32, Ct>;

// ============================================================================
// Positive fixtures — secret input tainted, output observed clean.
// ============================================================================
//
// `black_box` on each zero-init input before `taint_val` is
// load-bearing: without it the fat-LTO release build sees the
// concrete zero value, const-folds `SigningKey::from_seed` /
// `x25519` at compile time, and the runtime never actually reads the
// tainted memory — a false pass.
//
// The four positive fixtures are defined per carrier via the macro
// below. Extending to another carrier is one line.

macro_rules! positive_fixtures_for_carrier {
    ($carrier:ty, $signing_key:ident, $sign_fx:ident, $x25519_fx:ident, $x25519_base_fx:ident) => {
        ctgrind_fixture!($signing_key, {
            let seed = black_box([0u8; 32]);
            taint_val(&seed);
            if let Ok(sk) = SigningKey::<$carrier>::from_seed(&seed) {
                let pk = sk.public_key();
                // The public key is public — untaint before observing
                // so a stray propagated V-bit doesn't false-flag.
                untaint_val(&pk);
                let _ = black_box(pk);
            }
        });

        ctgrind_fixture!($sign_fx, {
            let seed = black_box([0u8; 32]);
            // Fixed public message — length + contents are public.
            let msg: &[u8] = b"ct-ctgrind message";
            taint_val(&seed);
            if let Ok(sk) = SigningKey::<$carrier>::from_seed(&seed) {
                if let Ok(sig) = sign(&sk, msg) {
                    untaint_val(&sig);
                    let _ = black_box(sig);
                }
            }
        });

        ctgrind_fixture!($x25519_fx, {
            let k = black_box([0u8; 32]);
            // u_in is the counterparty coordinate — public per RFC 7748.
            let u_in = black_box([0u8; 32]);
            taint_val(&k);
            let out = x25519::<$carrier>(&k, &u_in).unwrap_or([0u8; 32]);
            untaint_val(&out);
            let _ = black_box(out);
        });

        ctgrind_fixture!($x25519_base_fx, {
            let k = black_box([0u8; 32]);
            taint_val(&k);
            let out = x25519_base::<$carrier>(&k).unwrap_or([0u8; 32]);
            untaint_val(&out);
            let _ = black_box(out);
        });
    };
}

positive_fixtures_for_carrier!(
    T32x8,
    ct_fix__signing_key_from_seed__u32x8,
    ct_fix__sign__u32x8,
    ct_fix__x25519__u32x8,
    ct_fix__x25519_base__u32x8
);

positive_fixtures_for_carrier!(
    T32x16,
    ct_fix__signing_key_from_seed__u32x16,
    ct_fix__sign__u32x16,
    ct_fix__x25519__u32x16,
    ct_fix__x25519_base__u32x16
);

positive_fixtures_for_carrier!(
    T8x32,
    ct_fix__signing_key_from_seed__u8x32,
    ct_fix__sign__u8x32,
    ct_fix__x25519__u8x32,
    ct_fix__x25519_base__u8x32
);

krabi_caliper::ctgrind_standard_controls!();
