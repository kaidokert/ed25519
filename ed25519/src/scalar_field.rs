//! Factory for `modmath::FieldCt` over the Ed25519 scalar group order
//! `q = 2^252 + 27742317777372353535851937790883648493`.
//!
//! Sign computes `s = (r + k·a) mod q` where all three operands are
//! secret-derived, so the arithmetic runs on a `FieldCt<T>`. The
//! lifetime brand on `ResidueCt<'f, T>` prevents q-field residues from
//! flowing into a p-field operation — no separate type wrapper needed.
//!
//! `q` is odd and non-zero by construction; the `Odd<T>` typestate cut
//! discharges that proof once at the boundary so the `FieldCt`
//! constructor itself is infallible.

use crate::curve25519_field::CurveSetupError;
use crate::{Q_BYTES, UnsignedModularInt};
use modmath::{CiosMontMulCt, FieldCt, Parity, WideMul};

pub fn curve25519_ct<T>() -> Result<FieldCt<T>, CurveSetupError>
where
    T: UnsignedModularInt
        + Copy
        + PartialEq
        + const_num_traits::ops::overflowing::OverflowingAdd
        + const_num_traits::WrappingMul
        + const_num_traits::WrappingAdd
        + const_num_traits::WrappingSub
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
    let q = crate::from_le_bytes::<T>(&Q_BYTES);
    let q_odd = modmath::Odd::new(q).ok_or(CurveSetupError::InvalidModulus)?;
    Ok(FieldCt::new_odd(q_odd))
}
