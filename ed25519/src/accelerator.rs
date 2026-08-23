//! Complete Ed25519 and X25519 operation providers.
//!
//! These optional adapters fit singleton PKA peripherals and secure elements.
//! Existing `modmath` implementations remain the software fallback. Opaque-key
//! traits avoid exporting a hardware-root private key, while the exportable
//! X25519 adapter supports peripherals that accept a caller-owned scalar.

use signature::{RandomizedSigner, Signer, Verifier};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

/// Complete Ed25519 signing with a backend-owned private key.
pub trait Ed25519SignOperation {
    /// Backend-specific failure.
    type Error;

    /// Return the public key corresponding to the backend-owned private key.
    fn verifying_key(&self, output: &mut [u8; 32]) -> Result<(), Self::Error>;

    /// Produce a standard RFC 8032 signature.
    fn sign(&self, message: &[u8], signature: &mut [u8; 64]) -> Result<(), Self::Error>;

    /// Produce an RFC 8032-compatible signature hedged with fresh entropy.
    ///
    /// Providers without a hedged mode may retain deterministic Ed25519
    /// behavior by delegating to [`sign`](Self::sign).
    fn sign_hedged(
        &self,
        message: &[u8],
        _entropy: &[u8; 32],
        signature: &mut [u8; 64],
    ) -> Result<(), Self::Error> {
        self.sign(message, signature)
    }
}

/// Security marker for an Ed25519 private-key operation.
///
/// # Safety
///
/// The provider must protect the seed/expanded scalar and nonce under its
/// documented threat model, implement RFC 8032 scalar and point validation,
/// and verify a produced signature before returning it. Hedged implementations
/// must combine entropy without making nonce reuse possible when the RNG fails.
pub unsafe trait HardenedEd25519SignOperation: Ed25519SignOperation {}

/// Complete Ed25519 verification.
pub trait Ed25519VerifyOperation {
    /// Backend-specific failure.
    type Error;

    /// Verify a raw public key and standard 64-byte Ed25519 signature.
    fn verify(
        &self,
        public_key: &[u8; 32],
        message: &[u8],
        signature: &[u8; 64],
    ) -> Result<(), Self::Error>;
}

/// RustCrypto `signature` adapter for an opaque Ed25519 private key.
pub struct Ed25519SigningKey<A> {
    operation: A,
}

impl<A> Ed25519SigningKey<A> {
    /// Wrap a complete signing provider.
    pub const fn new(operation: A) -> Self {
        Self { operation }
    }

    /// Borrow the provider for lifecycle or diagnostics.
    pub fn operation(&self) -> &A {
        &self.operation
    }
}

impl<A: Ed25519SignOperation> Ed25519SigningKey<A> {
    /// Export only the matching public key.
    pub fn verifying_key_bytes(&self) -> Result<[u8; 32], A::Error> {
        let mut output = [0u8; 32];
        self.operation.verifying_key(&mut output)?;
        Ok(output)
    }
}

impl<A: HardenedEd25519SignOperation> Signer<[u8; 64]> for Ed25519SigningKey<A> {
    fn try_sign(&self, message: &[u8]) -> Result<[u8; 64], signature::Error> {
        let mut signature = [0u8; 64];
        if self.operation.sign(message, &mut signature).is_err() {
            signature.zeroize();
            return Err(signature::Error::new());
        }
        Ok(signature)
    }
}

impl<A: HardenedEd25519SignOperation> RandomizedSigner<[u8; 64]> for Ed25519SigningKey<A> {
    fn try_sign_with_rng<R: rand_core::TryCryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        message: &[u8],
    ) -> Result<[u8; 64], signature::Error> {
        let mut entropy = Zeroizing::new([0u8; 32]);
        rand_core::TryRng::try_fill_bytes(rng, &mut entropy[..])
            .map_err(|_| signature::Error::new())?;
        let mut signature = [0u8; 64];
        if self
            .operation
            .sign_hedged(message, &entropy, &mut signature)
            .is_err()
        {
            signature.zeroize();
            return Err(signature::Error::new());
        }
        Ok(signature)
    }
}

/// RustCrypto `signature` adapter for accelerated Ed25519 verification.
pub struct Ed25519VerifyingKey<A> {
    operation: A,
    public_key: [u8; 32],
}

impl<A> Ed25519VerifyingKey<A> {
    /// Wrap a provider and raw Ed25519 public key.
    pub const fn new(operation: A, public_key: [u8; 32]) -> Self {
        Self {
            operation,
            public_key,
        }
    }

    /// Return the wrapped public key.
    pub const fn to_bytes(&self) -> [u8; 32] {
        self.public_key
    }

    /// Borrow the provider for lifecycle or diagnostics.
    pub fn operation(&self) -> &A {
        &self.operation
    }
}

impl<A, S> Verifier<S> for Ed25519VerifyingKey<A>
where
    A: Ed25519VerifyOperation,
    S: AsRef<[u8]>,
{
    fn verify(&self, message: &[u8], signature: &S) -> Result<(), signature::Error> {
        let signature: &[u8; 64] = signature
            .as_ref()
            .try_into()
            .map_err(|_| signature::Error::new())?;
        self.operation
            .verify(&self.public_key, message, signature)
            .map_err(|_| signature::Error::new())
    }
}

/// Complete X25519 scalar multiplication for an exportable scalar.
pub trait X25519ScalarMultOperation {
    /// Backend-specific failure.
    type Error;

    /// Compute RFC 7748 X25519. The provider performs scalar clamping and
    /// masks the peer u-coordinate's high bit.
    fn scalar_mult(
        &self,
        scalar: &[u8; 32],
        peer_u: &[u8; 32],
        output: &mut [u8; 32],
    ) -> Result<(), Self::Error>;
}

/// Security marker for X25519 using caller-owned scalar bytes.
///
/// # Safety
///
/// Scalar-dependent timing, memory access, peripheral commands, and transfer
/// behavior must satisfy the provider's documented threat model.
pub unsafe trait HardenedX25519ScalarMultOperation: X25519ScalarMultOperation {}

/// Complete X25519 operations with a backend-owned opaque private key.
pub trait OpaqueX25519Operation {
    /// Backend-specific failure.
    type Error;

    /// Return the public u-coordinate for the opaque private key.
    fn public_key(&self, output: &mut [u8; 32]) -> Result<(), Self::Error>;

    /// Derive a shared secret with a peer u-coordinate.
    fn diffie_hellman(&self, peer_u: &[u8; 32], output: &mut [u8; 32]) -> Result<(), Self::Error>;
}

/// Security marker for opaque X25519 private-key operations.
///
/// # Safety
///
/// The private scalar must remain protected under the provider's documented
/// threat model, and the operation must implement RFC 7748 clamping and input
/// masking. The adapters independently reject an all-zero shared secret.
pub unsafe trait HardenedOpaqueX25519Operation: OpaqueX25519Operation {}

/// Failure from an X25519 adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X25519Error<E> {
    /// The operation provider failed.
    Backend(E),
    /// RFC 7748 produced the forbidden all-zero shared secret.
    LowOrderPoint,
}

fn reject_all_zero<E>(output: &mut [u8; 32]) -> Result<(), X25519Error<E>> {
    if bool::from(output.ct_eq(&[0u8; 32])) {
        output.zeroize();
        Err(X25519Error::LowOrderPoint)
    } else {
        Ok(())
    }
}

/// X25519 key using exportable, automatically wiped scalar bytes.
pub struct ExportableX25519Key<A> {
    operation: A,
    scalar: Zeroizing<[u8; 32]>,
}

impl<A> ExportableX25519Key<A> {
    /// Wrap a complete scalar-multiplication provider and scalar.
    pub fn new(operation: A, scalar: [u8; 32]) -> Self {
        Self {
            operation,
            scalar: Zeroizing::new(scalar),
        }
    }

    /// Borrow the provider for lifecycle or diagnostics.
    pub fn operation(&self) -> &A {
        &self.operation
    }
}

impl<A: HardenedX25519ScalarMultOperation> ExportableX25519Key<A> {
    /// Derive the public u-coordinate.
    pub fn public_key(&self) -> Result<[u8; 32], X25519Error<A::Error>> {
        let mut base = [0u8; 32];
        base[0] = 9;
        self.diffie_hellman(&base)
    }

    /// Derive and validate a shared secret.
    pub fn diffie_hellman(&self, peer_u: &[u8; 32]) -> Result<[u8; 32], X25519Error<A::Error>> {
        let mut output = [0u8; 32];
        self.operation
            .scalar_mult(&self.scalar, peer_u, &mut output)
            .map_err(X25519Error::Backend)?;
        reject_all_zero(&mut output)?;
        Ok(output)
    }
}

/// X25519 key whose private scalar remains inside the provider.
pub struct OpaqueX25519Key<A> {
    operation: A,
}

impl<A> OpaqueX25519Key<A> {
    /// Wrap an opaque-key provider.
    pub const fn new(operation: A) -> Self {
        Self { operation }
    }

    /// Borrow the provider for lifecycle or diagnostics.
    pub fn operation(&self) -> &A {
        &self.operation
    }
}

impl<A: HardenedOpaqueX25519Operation> OpaqueX25519Key<A> {
    /// Export only the public u-coordinate.
    pub fn public_key(&self) -> Result<[u8; 32], X25519Error<A::Error>> {
        let mut output = [0u8; 32];
        self.operation
            .public_key(&mut output)
            .map_err(X25519Error::Backend)?;
        reject_all_zero(&mut output)?;
        Ok(output)
    }

    /// Derive and validate a shared secret without exporting the scalar.
    pub fn diffie_hellman(&self, peer_u: &[u8; 32]) -> Result<[u8; 32], X25519Error<A::Error>> {
        let mut output = [0u8; 32];
        self.operation
            .diffie_hellman(peer_u, &mut output)
            .map_err(X25519Error::Backend)?;
        reject_all_zero(&mut output)?;
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;

    struct MockEd25519(Cell<u32>);

    impl Ed25519SignOperation for MockEd25519 {
        type Error = ();

        fn verifying_key(&self, output: &mut [u8; 32]) -> Result<(), Self::Error> {
            output.fill(0x11);
            Ok(())
        }

        fn sign(&self, message: &[u8], signature: &mut [u8; 64]) -> Result<(), Self::Error> {
            self.0.set(self.0.get() + 1);
            signature[..message.len()].copy_from_slice(message);
            Ok(())
        }
    }

    unsafe impl HardenedEd25519SignOperation for MockEd25519 {}

    impl Ed25519VerifyOperation for MockEd25519 {
        type Error = ();

        fn verify(
            &self,
            _: &[u8; 32],
            message: &[u8],
            signature: &[u8; 64],
        ) -> Result<(), Self::Error> {
            (signature[..message.len()] == *message)
                .then_some(())
                .ok_or(())
        }
    }

    struct MockX25519;

    impl X25519ScalarMultOperation for MockX25519 {
        type Error = ();

        fn scalar_mult(
            &self,
            scalar: &[u8; 32],
            peer_u: &[u8; 32],
            output: &mut [u8; 32],
        ) -> Result<(), Self::Error> {
            for ((output, scalar), peer) in output.iter_mut().zip(scalar).zip(peer_u) {
                *output = scalar ^ peer;
            }
            Ok(())
        }
    }

    unsafe impl HardenedX25519ScalarMultOperation for MockX25519 {}

    struct MockOpaqueX25519;

    impl OpaqueX25519Operation for MockOpaqueX25519 {
        type Error = ();

        fn public_key(&self, output: &mut [u8; 32]) -> Result<(), Self::Error> {
            output.fill(0x33);
            Ok(())
        }

        fn diffie_hellman(
            &self,
            peer_u: &[u8; 32],
            output: &mut [u8; 32],
        ) -> Result<(), Self::Error> {
            output.copy_from_slice(peer_u);
            Ok(())
        }
    }

    unsafe impl HardenedOpaqueX25519Operation for MockOpaqueX25519 {}

    #[test]
    fn ed25519_signature_adapters_keep_message_and_key_ownership_separate() {
        let signer = Ed25519SigningKey::new(MockEd25519(Cell::new(0)));
        let signature = signer.try_sign(b"boot image").unwrap();
        assert_eq!(&signature[..10], b"boot image");
        assert_eq!(signer.operation().0.get(), 1);
        assert_eq!(signer.verifying_key_bytes().unwrap(), [0x11; 32]);

        let verifier = Ed25519VerifyingKey::new(MockEd25519(Cell::new(0)), [0x11; 32]);
        verifier.verify(b"boot image", &signature).unwrap();
    }

    #[test]
    fn exportable_x25519_rejects_and_wipes_all_zero_secret() {
        let scalar = [0x5a; 32];
        let key = ExportableX25519Key::new(MockX25519, scalar);
        assert_eq!(key.diffie_hellman(&scalar), Err(X25519Error::LowOrderPoint));
        assert_ne!(key.public_key().unwrap(), [0; 32]);
    }

    #[test]
    fn opaque_x25519_exports_only_public_and_shared_values() {
        let key = OpaqueX25519Key::new(MockOpaqueX25519);
        assert_eq!(key.public_key().unwrap(), [0x33; 32]);
        assert_eq!(key.diffie_hellman(&[0x44; 32]).unwrap(), [0x44; 32]);
        assert_eq!(
            key.diffie_hellman(&[0; 32]),
            Err(X25519Error::LowOrderPoint)
        );
    }
}
