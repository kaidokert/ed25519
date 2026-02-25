// Montgomery-domain lazy field operations for Ed25519.
// Drop-in replacements for lazy_field.rs functions that operate in Montgomery domain.
// Addition and subtraction are identical to normal (just add/sub mod p).
// Only multiplication changes — uses wide_montgomery_mul instead of (a * b) % p.

use crate::montgomery_ctx::MontgomeryCtx;
use crate::BrigIntStrict;
use modmath::{WideMul, CiosMontMul};

/// Montgomery-domain modular multiplication.
/// Both a and b must already be in Montgomery form.
/// Result is in Montgomery form.
#[inline]
pub fn mont_mod_mul<T>(a: T, b: &T, ctx: &MontgomeryCtx<T>) -> T
where
    T: BrigIntStrict
        + Copy
        + WideMul
        + CiosMontMul
        + num_traits::ops::overflowing::OverflowingAdd
        + num_traits::WrappingMul
        + num_traits::WrappingAdd
        + num_traits::WrappingSub,
{
    ctx.mont_mul(a, *b)
}
