// Lazy field arithmetic for Ed25519 - avoids unnecessary reductions
// Assumes inputs are already reduced (< p) unless specified otherwise

/// Lazy modular addition: assumes a, b < p, result < 2p
/// Only reduces if result >= p (cheap comparison vs expensive division)
pub fn lazy_mod_add<T: PartialOrd>(a: T, b: &T, p: &T) -> T
where
    for<'a> &'a T: core::ops::Add<&'a T, Output = T> + core::ops::Sub<&'a T, Output = T>,
{
    let sum = &a + b;
    if &sum >= p {
        &sum - p // Single subtraction vs expensive division
    } else {
        sum
    }
}

/// Lazy modular subtraction: assumes a, b < p
/// Adds p if result would be negative (cheaper than full reduction)
pub fn lazy_mod_sub<T: PartialOrd>(a: T, b: &T, p: &T) -> T
where
    for<'a> &'a T: core::ops::Add<&'a T, Output = T> + core::ops::Sub<&'a T, Output = T>,
{
    if &a >= b {
        &a - b
    } else {
        &(&a + p) - b // Add p then subtract (result < p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lazy_add() {
        let p = 23u64; // Small prime for testing
        let a = 10u64;
        let b = 5u64;

        let result = lazy_mod_add(a, &b, &p);
        assert_eq!(result, 15); // 10 + 5 = 15 < 23

        let a2 = 20u64;
        let result2 = lazy_mod_add(a2, &b, &p);
        assert_eq!(result2, 2); // 20 + 5 = 25, 25 - 23 = 2
    }

    #[test]
    fn test_lazy_sub() {
        let p = 23u64;
        let a = 15u64;
        let b = 10u64;

        let result = lazy_mod_sub(a, &b, &p);
        assert_eq!(result, 5); // 15 - 10 = 5

        let a2 = 5u64;
        let result2 = lazy_mod_sub(a2, &b, &p);
        assert_eq!(result2, 18); // 5 - 10 + 23 = 18
    }
}
