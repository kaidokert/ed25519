// Benchmark F25519 vs FixedUInt<u64, 8> performance
// Run with: cargo run --bin benchmark_f25519 --features="fixed-bigint,fixed-bigint-u64,std" --release

use std::time::Instant;

fn main() {
    println!("=== F25519 vs FixedUInt<u64,8> Performance Comparison ===");
    
    const ITERATIONS: usize = 100_000;
    
    // Test F25519 performance
    println!("Testing F25519 field arithmetic...");
    let a_f25519 = ed25519n::field25519::F25519::from_bytes_le(&[0x42; 32]);
    let b_f25519 = ed25519n::field25519::F25519::from_bytes_le(&[0x37; 32]);
    
    let start = Instant::now();
    let mut result_f25519 = a_f25519;
    for _ in 0..ITERATIONS {
        result_f25519 = result_f25519 * b_f25519;
    }
    let f25519_time = start.elapsed();
    
    println!("F25519: {} iterations in {:.3}ms", ITERATIONS, f25519_time.as_secs_f64() * 1000.0);
    println!("F25519: {:.3}μs per multiplication", f25519_time.as_secs_f64() * 1_000_000.0 / ITERATIONS as f64);
    
    // Test FixedUInt<u64, 8> performance  
    println!("\nTesting FixedUInt<u64, 8> arithmetic...");
    let a_fixed = fixed_bigint::FixedUInt::<u64, 8>::from_le_bytes(&[0x42; 64]);
    let b_fixed = fixed_bigint::FixedUInt::<u64, 8>::from_le_bytes(&[0x37; 64]);
    
    let start = Instant::now();
    let mut result_fixed = a_fixed;
    for _ in 0..ITERATIONS {
        result_fixed = result_fixed * b_fixed;
    }
    let fixed_time = start.elapsed();
    
    println!("FixedUInt: {} iterations in {:.3}ms", ITERATIONS, fixed_time.as_secs_f64() * 1000.0);
    println!("FixedUInt: {:.3}μs per multiplication", fixed_time.as_secs_f64() * 1_000_000.0 / ITERATIONS as f64);
    
    // Compare performance
    let speedup = fixed_time.as_secs_f64() / f25519_time.as_secs_f64();
    println!("\n=== Performance Comparison ===");
    println!("F25519 is {:.1}x faster than FixedUInt<u64, 8>", speedup);
    
    if speedup > 4.0 {
        println!("🚀 EXCELLENT: >4x speedup from specialized arithmetic!");
    } else if speedup > 2.0 {
        println!("✅ GOOD: >2x speedup from specialized arithmetic");
    } else if speedup > 1.2 {
        println!("⚠️ MODERATE: Some improvement from specialization");
    } else {
        println!("❌ POOR: No significant improvement");
    }
    
    println!("\n=== Ed25519 Impact Estimate ===");
    println!("Current Ed25519 verification: ~30ms");
    println!("With F25519 arithmetic: ~{:.1}ms (estimated)", 30.0 / speedup);
    println!("Target (production): 0.032ms");
    
    let remaining_gap = (30.0 / speedup) / 0.032;
    println!("Remaining performance gap: {:.0}x", remaining_gap);
}