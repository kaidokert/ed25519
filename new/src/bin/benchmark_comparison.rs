// Benchmark comparison between our implementation and ed25519-dalek
// Run with: cargo run --bin benchmark_comparison --features="fixed-bigint,fixed-bigint-u64,std" --release

use std::time::Instant;
use ed25519_dalek::{Verifier, Signature, VerifyingKey};

// Ed25519 test vectors (same as our implementation)
const PUBLIC_KEY: [u8; 32] = [
    0x33, 0xbc, 0x91, 0xa3, 0xca, 0xb8, 0x87, 0xc8, 0xbf, 0x3c, 0x63, 0x61, 0x46, 0xd2, 0xe3, 0x8d,
    0x58, 0xd0, 0xca, 0xf3, 0x3b, 0x77, 0x86, 0x25, 0xc7, 0x95, 0x2b, 0xc7, 0x6f, 0xc0, 0x73, 0xac,
];

const SIGNATURE: [u8; 64] = [
    0x2f, 0xec, 0x62, 0xdf, 0x49, 0x4f, 0xf5, 0x70, 0x5f, 0x5c, 0xee, 0x45, 0xbc, 0x5e, 0x89, 0xc2,
    0x32, 0xc1, 0x61, 0x88, 0x37, 0x87, 0xce, 0x50, 0xa2, 0x9b, 0xe8, 0x8c, 0xb1, 0x92, 0xc8, 0x81,
    0x25, 0x62, 0x74, 0xed, 0xd7, 0x67, 0x2a, 0xa5, 0x52, 0x79, 0x57, 0xeb, 0x0d, 0xdc, 0x0e, 0x60,
    0x95, 0x23, 0x74, 0x36, 0x22, 0x32, 0x85, 0xf6, 0xd9, 0x30, 0x6b, 0x96, 0x63, 0x14, 0x86, 0x02,
];

const MESSAGE: &[u8] = b"Hello world!\n";
const ITERATIONS: usize = 100;

fn benchmark_dalek() -> (f64, f64) {
    let verifying_key = VerifyingKey::from_bytes(&PUBLIC_KEY).expect("Invalid public key");
    let signature = Signature::from_bytes(&SIGNATURE);
    
    // Warmup
    for _ in 0..100 {
        let _ = verifying_key.verify(MESSAGE, &signature);
    }
    
    println!("Benchmarking ed25519-dalek ({} iterations)...", ITERATIONS);
    let start = Instant::now();
    let mut successes = 0;
    
    for _ in 0..ITERATIONS {
        if verifying_key.verify(MESSAGE, &signature).is_ok() {
            successes += 1;
        }
    }
    
    let total_time = start.elapsed();
    let avg_time_us = total_time.as_nanos() as f64 / 1000.0 / ITERATIONS as f64;
    let ops_per_sec = 1_000_000.0 / avg_time_us;
    
    println!("ed25519-dalek results:");
    println!("  Success rate: {}/{}", successes, ITERATIONS);
    println!("  Total time: {:.3}ms", total_time.as_secs_f64() * 1000.0);
    println!("  Average time: {:.3}μs", avg_time_us);
    println!("  Throughput: {:.0} ops/sec", ops_per_sec);
    
    (avg_time_us, ops_per_sec)
}

fn benchmark_ours() -> (f64, f64) {
    // Disable logging to avoid measurement overhead
    unsafe { std::env::set_var("RUST_LOG", "off") };

    // Warmup
    for _ in 0..10 {
        #[cfg(feature = "fixed-bigint-256")]
        let _ = ed25519n::strict::verify::<fixed_bigint::FixedUInt<u64, 4>>(
            PUBLIC_KEY, MESSAGE, SIGNATURE,
        );
        #[cfg(not(feature = "fixed-bigint-256"))]
        let _ = ed25519n::strict::verify::<fixed_bigint::FixedUInt<u64, 8>>(
            PUBLIC_KEY, MESSAGE, SIGNATURE,
        );
    }

    println!("Benchmarking our implementation ({} iterations)...", ITERATIONS);
    let start = Instant::now();
    let mut successes = 0;

    for _ in 0..ITERATIONS {
        #[cfg(feature = "fixed-bigint-256")]
        let result = ed25519n::strict::verify::<fixed_bigint::FixedUInt<u64, 4>>(
            PUBLIC_KEY, MESSAGE, SIGNATURE,
        );
        #[cfg(not(feature = "fixed-bigint-256"))]
        let result = ed25519n::strict::verify::<fixed_bigint::FixedUInt<u64, 8>>(
            PUBLIC_KEY, MESSAGE, SIGNATURE,
        );
        if result {
            successes += 1;
        }
    }
    
    let total_time = start.elapsed();
    let avg_time_us = total_time.as_nanos() as f64 / 1000.0 / ITERATIONS as f64;
    let ops_per_sec = 1_000_000.0 / avg_time_us;
    
    println!("Our implementation results:");
    println!("  Success rate: {}/{}", successes, ITERATIONS);
    println!("  Total time: {:.3}ms", total_time.as_secs_f64() * 1000.0);
    println!("  Average time: {:.3}μs", avg_time_us);
    println!("  Throughput: {:.0} ops/sec", ops_per_sec);
    
    (avg_time_us, ops_per_sec)
}

fn main() {
    println!("=== Ed25519 Performance Comparison ===\n");
    
    let (dalek_time, dalek_ops) = benchmark_dalek();
    println!();
    let (ours_time, ours_ops) = benchmark_ours();
    
    println!("\n=== Comparison ===");
    println!("ed25519-dalek: {:.1}μs ({:.0} ops/sec)", dalek_time, dalek_ops);
    println!("Our implementation: {:.1}μs ({:.0} ops/sec)", ours_time, ours_ops);
    
    let slowdown = ours_time / dalek_time;
    println!("Our implementation is {:.1}x slower", slowdown);
    
    if slowdown > 100.0 {
        println!("🐌 CRITICAL: Over 100x slower than production");
    } else if slowdown > 10.0 {
        println!("⚠️ WARNING: Over 10x slower than production");
    } else if slowdown > 2.0 {
        println!("⚠️ MODERATE: Over 2x slower than production");
    } else {
        println!("✅ GOOD: Competitive with production");
    }
}