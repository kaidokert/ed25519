// Lazy field arithmetic for Ed25519 - avoids unnecessary reductions
// Assumes inputs are already reduced (< p) unless specified otherwise

use crate::BrigIntStrict;

/// Lazy modular addition: assumes a, b < p, result < 2p
/// Only reduces if result >= p (cheap comparison vs expensive division)
pub fn lazy_mod_add<T: BrigIntStrict>(a: T, b: &T, p: &T) -> T
where
    for<'a> &'a T: core::ops::Add<&'a T, Output = T>
        + core::ops::Sub<&'a T, Output = T>,
{
    let sum = &a + b;
    if &sum >= p {
        &sum - p  // Single subtraction vs expensive division
    } else {
        sum
    }
}

/// Lazy modular subtraction: assumes a, b < p
/// Adds p if result would be negative (cheaper than full reduction)
pub fn lazy_mod_sub<T: BrigIntStrict>(a: T, b: &T, p: &T) -> T
where
    for<'a> &'a T: core::ops::Add<&'a T, Output = T>
        + core::ops::Sub<&'a T, Output = T>,
{
    if &a >= b {
        &a - b
    } else {
        &(&a + p) - b  // Add p then subtract (result < p)
    }
}

/// Lazy modular multiplication: multiply then reduce once
/// Still expensive but avoids double reduction of inputs
pub fn lazy_mod_mul<T: BrigIntStrict>(a: T, b: &T, p: &T) -> T
where
    for<'a> &'a T: core::ops::Mul<&'a T, Output = T>
        + core::ops::Rem<&'a T, Output = T>,
{
    let product = &a * b;
    #[cfg(feature = "instrument")]
    modmath::instrument::LAZY_MUL_REM.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    product % p  // Single reduction on result
}

/// Force full reduction when needed (e.g., before comparisons)
pub fn force_reduce<T: BrigIntStrict>(a: T, p: &T) -> T
where
    for<'a> &'a T: core::ops::Rem<&'a T, Output = T>,
{
    #[cfg(feature = "instrument")]
    modmath::instrument::LAZY_FORCE_REDUCE.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    a % p
}

/// Check if value needs reduction (>= p)
pub fn needs_reduction<T: BrigIntStrict>(a: &T, p: &T) -> bool {
    a >= p
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_lazy_add() {
        let p = 23u64;  // Small prime for testing
        let a = 10u64;
        let b = 5u64;
        
        let result = lazy_mod_add(a, &b, &p);
        assert_eq!(result, 15);  // 10 + 5 = 15 < 23
        
        let a2 = 20u64;
        let result2 = lazy_mod_add(a2, &b, &p);
        assert_eq!(result2, 2);  // 20 + 5 = 25, 25 - 23 = 2
    }
    
    #[test]
    fn test_lazy_sub() {
        let p = 23u64;
        let a = 15u64;
        let b = 10u64;
        
        let result = lazy_mod_sub(a, &b, &p);
        assert_eq!(result, 5);   // 15 - 10 = 5
        
        let a2 = 5u64;
        let result2 = lazy_mod_sub(a2, &b, &p);
        assert_eq!(result2, 18); // 5 - 10 + 23 = 18
    }
}