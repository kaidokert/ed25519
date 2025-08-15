// Profile timing breakdown of our Ed25519 implementation
// Run with: cargo run --bin profile_timing --features="fixed-bigint,fixed-bigint-u64,std" --release

use std::time::Instant;

// Ed25519 test vectors
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
const ITERATIONS: usize = 10; // Fewer iterations for detailed profiling

fn profile_single_operation() {
    unsafe { std::env::set_var("RUST_LOG", "off") };

    println!("=== Profiling Single Ed25519 Verification ===");
    
    // Single verification with detailed breakdown
    let start = Instant::now();
    let result = ed25519n::strict::verify::<fixed_bigint::FixedUInt<u64, 8>>(
        PUBLIC_KEY, MESSAGE, SIGNATURE,
    );
    let total_time = start.elapsed();
    
    println!("Result: {}", if result { "ACCEPT" } else { "REJECT" });
    println!("Total time: {:.3}ms", total_time.as_secs_f64() * 1000.0);
    println!("Total time: {:.1}μs", total_time.as_nanos() as f64 / 1000.0);
}

fn profile_batch_operations() {
    unsafe { std::env::set_var("RUST_LOG", "off") };
    
    println!("\n=== Profiling Batch Operations ===");
    
    let mut times = Vec::new();
    let mut successes = 0;
    
    for i in 0..ITERATIONS {
        let start = Instant::now();
        let result = ed25519n::strict::verify::<fixed_bigint::FixedUInt<u64, 8>>(
            PUBLIC_KEY, MESSAGE, SIGNATURE,
        );
        let elapsed = start.elapsed();
        
        if result { successes += 1; }
        times.push(elapsed.as_nanos() as f64 / 1000.0); // Convert to microseconds
        
        println!("Run {}: {:.1}μs", i + 1, elapsed.as_nanos() as f64 / 1000.0);
    }
    
    let total_time: f64 = times.iter().sum();
    let avg_time = total_time / times.len() as f64;
    let min_time = times.iter().cloned().fold(f64::INFINITY, f64::min);
    let max_time = times.iter().cloned().fold(0.0, f64::max);
    
    println!("\n=== Batch Results ===");
    println!("Successes: {}/{}", successes, ITERATIONS);
    println!("Average time: {:.1}μs", avg_time);
    println!("Min time: {:.1}μs", min_time);
    println!("Max time: {:.1}μs", max_time);
    println!("Throughput: {:.0} ops/sec", 1_000_000.0 / avg_time);
}

fn compare_modmath_backends() {
    println!("\n=== Comparing Different Arithmetic Modes ===");
    
    // Basic mode
    let start = Instant::now();
    let result = ed25519n::basic::verify::<fixed_bigint::FixedUInt<u64, 8>>(PUBLIC_KEY, MESSAGE, SIGNATURE);
    let elapsed = start.elapsed();
    println!("Basic mode: {:.1}μs ({})", 
             elapsed.as_nanos() as f64 / 1000.0,
             if result { "ACCEPT" } else { "REJECT" });
    
    // Constrained mode 
    let start = Instant::now();
    let result = ed25519n::constrained::verify::<fixed_bigint::FixedUInt<u64, 8>>(PUBLIC_KEY, MESSAGE, SIGNATURE);
    let elapsed = start.elapsed();
    println!("Constrained mode: {:.1}μs ({})", 
             elapsed.as_nanos() as f64 / 1000.0,
             if result { "ACCEPT" } else { "REJECT" });
    
    // Strict mode
    let start = Instant::now();
    let result = ed25519n::strict::verify::<fixed_bigint::FixedUInt<u64, 8>>(PUBLIC_KEY, MESSAGE, SIGNATURE);
    let elapsed = start.elapsed();
    println!("Strict mode: {:.1}μs ({})", 
             elapsed.as_nanos() as f64 / 1000.0,
             if result { "ACCEPT" } else { "REJECT" });
}

fn main() {
    profile_single_operation();
    profile_batch_operations();
    compare_modmath_backends();
    
    println!("\n=== Performance Analysis ===");
    println!("Target: ~32μs (production ed25519-dalek)");
    println!("Current: ~39,000μs (our implementation)");
    println!("Gap: ~1,200x slower");
    println!("\nKey bottlenecks to investigate:");
    println!("1. Generic bigint operations vs specialized field arithmetic");
    println!("2. Point scalar multiplication algorithm efficiency");
    println!("3. Extended coordinate system overhead");
    println!("4. Missing precomputed tables/windowing");
}