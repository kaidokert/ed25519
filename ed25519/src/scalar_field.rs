//! Factory for `modmath::FieldCt` over the Ed25519 scalar group order
//! `q = 2^252 + 27742317777372353535851937790883648493`.
//!
//! Sign computes `s = (r + k·a) mod q` where all three operands are
//! secret-derived, so the arithmetic runs on a `FieldCt<T>`. The
//! lifetime brand on `ResidueCt<'f, T>` prevents q-field residues from
//! flowing into a p-field operation — no separate type wrapper needed.
//!
//! `q` is odd and non-zero by construction; `modmath::FieldCt::new`
//! still returns `Option` because it can't know which modulus we're
//! passing. Discharge once at field construction.

use crate::curve25519_field::CurveSetupError;
use crate::{Q_BYTES, UnsignedModularInt};
use modmath::{CiosMontMulCt, FieldCt, Parity, WideMul};

pub fn curve25519_ct<T>() -> Result<FieldCt<T>, CurveSetupError>
where
    T: UnsignedModularInt
        + Copy
        + PartialEq
        + num_traits::ops::overflowing::OverflowingAdd
        + num_traits::WrappingMul
        + num_traits::WrappingAdd
        + num_traits::WrappingSub
        + Parity
        + WideMul
        + CiosMontMulCt
        + subtle::ConditionallySelectable
        + subtle::ConstantTimeLess,
    for<'a> &'a T: core::ops::Add<&'a T, Output = T> + core::ops::Sub<&'a T, Output = T>,
{
    if modmath::type_bit_width::<T>() < 256 {
        return Err(CurveSetupError::BackendTooNarrow);
    }
    let q = T::from_bytes_le(&Q_BYTES);
    FieldCt::new(q).ok_or(CurveSetupError::InvalidModulus)
}
