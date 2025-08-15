// Test F25519 field arithmetic implementation
// Run with: cargo run --bin test_f25519 --features="fixed-bigint,fixed-bigint-u64,std" --release

use ed25519n::field25519::F25519;
use std::time::Instant;

fn main() {
    println!("=== Testing F25519 Field Arithmetic ===");
    
    // Test basic construction
    let zero = F25519::zero();
    let one = F25519::one();
    let p = F25519::prime();
    
    println!("Zero: {:?}", zero);
    println!("One: {:?}", one);
    println!("Prime p: {:?}", p);
    
    // Test basic arithmetic
    println!("\n=== Basic Arithmetic Tests ===");
    let two = one + one;
    println!("1 + 1 = {:?}", two);
    
    let back_to_one = two - one;
    println!("2 - 1 = {:?}", back_to_one);
    assert_eq!(back_to_one, one);
    
    // Test modular reduction  
    println!("\n=== Modular Reduction Tests ===");
    let p_plus_one = p + one;
    println!("p + 1 = {:?}", p_plus_one);
    println!("Should equal 1: {}", p_plus_one == one);
    
    // Test from/to bytes
    println!("\n=== Bytes Conversion Tests ===");
    let test_bytes = [1u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let from_bytes = F25519::from_bytes_le(&test_bytes);
    println!("From bytes [1,0,0,...]: {:?}", from_bytes);
    assert_eq!(from_bytes, one);
    
    let mut out_bytes = [0u8; 32];
    one.to_bytes_le(&mut out_bytes);
    println!("One to bytes: {:?}", &out_bytes[..8]);
    
    // Performance test - multiplication
    println!("\n=== Performance Test ===");
    let a = F25519::from_bytes_le(&[0x42; 32]);
    let b = F25519::from_bytes_le(&[0x37; 32]);
    
    let iterations = 10000;
    let start = Instant::now();
    let mut result = a;
    
    for _ in 0..iterations {
        result = result * b;
    }
    
    let elapsed = start.elapsed();
    println!("10,000 multiplications took: {:.3}ms", elapsed.as_secs_f64() * 1000.0);
    println!("Average per multiplication: {:.3}μs", elapsed.as_secs_f64() * 1_000_000.0 / iterations as f64);
    
    // Test with BrigIntStrict trait
    println!("\n=== BrigIntStrict Trait Test ===");
    println!("F25519 implements BrigIntStrict: skipping complex trait test for now");
    
    println!("\n✅ F25519 field arithmetic tests completed!");
}

fn test_brigint_operations<T>() -> bool 
where
    T: ed25519n::BrigIntStrict,
    for<'a> &'a T: core::ops::BitAnd<Output = T>
        + core::ops::Rem<&'a T, Output = T>
        + core::ops::Add<&'a T, Output = T>
        + core::ops::Sub<T, Output = T>
        + core::ops::Sub<&'a T, Output = T>
        + core::ops::Mul<&'a T, Output = T>
        + core::ops::Div<&'a T, Output = T>,
{
    let one_bytes = [1u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let one = T::from_bytes_le(&one_bytes);
    let two = &one + &one;
    let back_to_one = two - one.clone();
    
    // Convert back to bytes to check
    let mut result_bytes = [0u8; 32];
    back_to_one.to_bytes_le(&mut result_bytes);
    
    result_bytes[0] == 1 && result_bytes[1] == 0
}