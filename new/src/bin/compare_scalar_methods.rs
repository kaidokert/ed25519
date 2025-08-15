// Compare JSF vs Shamir's trick vs Binary scalar multiplication
// Run with: cargo run --bin compare_scalar_methods --features="fixed-bigint,fixed-bigint-u64,std" --release

use std::time::Instant;

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

fn main() {
    unsafe { std::env::set_var("RUST_LOG", "off") };
    
    println!("=== Scalar Multiplication Method Comparison ===");
    
    // Run each verification method multiple times
    const ITERATIONS: usize = 5;
    
    println!("Testing {} iterations of each method...\n", ITERATIONS);
    
    // Test JSF method (current)
    println!("=== JSF Method ===");
    let mut jsf_times = Vec::new();
    let mut jsf_success = 0;
    
    for i in 0..ITERATIONS {
        let start = Instant::now();
        let result = ed25519n::strict::verify::<fixed_bigint::FixedUInt<u64, 8>>(
            PUBLIC_KEY, MESSAGE, SIGNATURE,
        );
        let elapsed = start.elapsed();
        
        if result { jsf_success += 1; }
        jsf_times.push(elapsed.as_secs_f64() * 1000.0);
        println!("Run {}: {:.1}ms ({})", i+1, elapsed.as_secs_f64() * 1000.0, 
                 if result { "✓" } else { "✗" });
    }
    
    let jsf_avg = jsf_times.iter().sum::<f64>() / jsf_times.len() as f64;
    let jsf_min = jsf_times.iter().cloned().fold(f64::INFINITY, f64::min);
    let jsf_max = jsf_times.iter().cloned().fold(0.0, f64::max);
    
    println!("JSF Results:");
    println!("  Average: {:.1}ms", jsf_avg);
    println!("  Min: {:.1}ms", jsf_min);
    println!("  Max: {:.1}ms", jsf_max);
    println!("  Success: {}/{}", jsf_success, ITERATIONS);
    
    // Analyze JSF efficiency with actual Ed25519 scalars
    println!("\n=== JSF Analysis with Real Ed25519 Scalars ===");
    
    // Extract scalars from our test signature
    let s_bytes: [u8; 32] = SIGNATURE[32..64].try_into().unwrap();
    let s = fixed_bigint::FixedUInt::<u64, 8>::from_le_bytes(&{
        let mut full_bytes = [0u8; 64];
        full_bytes[..32].copy_from_slice(&s_bytes);
        full_bytes
    });
    
    // Create a test h scalar (in real verification this comes from hash)
    let h_test_bytes = [0x42; 32];
    let h = fixed_bigint::FixedUInt::<u64, 8>::from_le_bytes(&{
        let mut full_bytes = [0u8; 64];
        full_bytes[..32].copy_from_slice(&h_test_bytes);
        full_bytes
    });
    
    let jsf = ed25519n::jsf::JsfIterator::new(s, h);
    let stats = ed25519n::jsf::JsfStats::analyze(&jsf);
    
    println!("Ed25519 JSF Statistics:");
    println!("  Total bits: {}", stats.total_digits);
    println!("  Nonzero operations: {}", stats.total_nonzero);
    println!("  Efficiency vs binary: {:.1}% reduction", stats.efficiency_vs_binary * 100.0);
    
    // Estimate what binary double scalar would cost
    let binary_ops = stats.total_digits * 2; // Rough estimate
    println!("  Estimated binary ops: {}", binary_ops);
    println!("  JSF ops: {}", stats.total_nonzero);
    println!("  Theoretical speedup: {:.2}x", binary_ops as f64 / stats.total_nonzero as f64);
    
    println!("\n=== Conclusions ===");
    println!("Current JSF performance: {:.1}ms average", jsf_avg);
    println!("Target (production): 0.032ms");
    println!("Still need: {:.0}x improvement", jsf_avg / 0.032);
    
    if jsf_avg > 30.0 {
        println!("❌ JSF slower than expected - investigate implementation");
    } else if jsf_avg > 15.0 {
        println!("⚠️ JSF showing some improvement but still slow");
    } else {
        println!("✅ JSF showing good improvement");
    }
    
    println!("\nNext steps:");
    println!("1. Implement dedicated Edwards doubling (vs generic point_add)");
    println!("2. Use cached/Niels forms for point additions");
    println!("3. Bytewise bit reading instead of bigint shifts");
    println!("4. Barrett/Montgomery reduction in field operations");
}