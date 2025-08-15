// Test JSF (Joint Sparse Form) implementation
// Run with: cargo run --bin test_jsf --features="fixed-bigint,fixed-bigint-u64,std" --release

use ed25519n::jsf::{JsfIterator, JsfStats};
use std::time::Instant;

fn main() {
    println!("=== Testing JSF (Joint Sparse Form) Implementation ===");
    
    // Test with small values first
    println!("=== Basic JSF Test ===");
    let s_bytes = [0x23, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let h_bytes = [0x56, 0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let s = fixed_bigint::FixedUInt::<u64, 8>::from_le_bytes(&s_bytes);
    let h = fixed_bigint::FixedUInt::<u64, 8>::from_le_bytes(&h_bytes);
    
    println!("Testing with s = 0x{:x}, h = 0x{:x}", s, h);
    
    let jsf = JsfIterator::new(s, h);
    let stats = JsfStats::analyze(&jsf);
    
    println!("JSF Statistics:");
    println!("  Total digits: {}", stats.total_digits);
    println!("  S nonzero digits: {} ({:.1}% density)", stats.s_nonzero, 
             100.0 * stats.s_nonzero as f64 / stats.total_digits as f64);
    println!("  H nonzero digits: {} ({:.1}% density)", stats.h_nonzero,
             100.0 * stats.h_nonzero as f64 / stats.total_digits as f64);
    println!("  Total nonzero: {} ({:.1}% of total)", stats.total_nonzero,
             100.0 * stats.total_nonzero as f64 / stats.total_digits as f64);
    println!("  Efficiency vs binary: {:.1}% reduction in additions", 
             stats.efficiency_vs_binary * 100.0);
    
    // Show the actual digits
    println!("\nJSF digits (MSB first):");
    for (i, digit) in jsf.digits_msb_first().enumerate() {
        if i > 10 { println!("  ... (showing first 10)"); break; }
        println!("  bit {}: s={:2}, h={:2}", stats.total_digits - 1 - i, 
                 digit.s_digit, digit.h_digit);
    }
    
    // Test with Ed25519-sized scalars
    println!("\n=== Ed25519 Scale Test ===");
    let s_large_bytes = [0xef, 0xcd, 0xab, 0x90, 0x78, 0x56, 0x34, 0x12, 0x21, 0x43, 0x65, 0x87, 0x09, 0xba, 0xdc, 0xfe,
                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let h_large_bytes = [0xba, 0xdc, 0xfe, 0x10, 0x32, 0x54, 0x76, 0x98, 0xf0, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12,
                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let s_test = fixed_bigint::FixedUInt::<u64, 8>::from_le_bytes(&s_large_bytes);
    let h_test = fixed_bigint::FixedUInt::<u64, 8>::from_le_bytes(&h_large_bytes);
    
    println!("Testing with large scalars...");
    let jsf_large = JsfIterator::new(s_test, h_test);
    let stats_large = JsfStats::analyze(&jsf_large);
    
    println!("Large JSF Statistics:");
    println!("  Total digits: {}", stats_large.total_digits);
    println!("  Total nonzero: {} ({:.1}% density)", stats_large.total_nonzero,
             100.0 * stats_large.total_nonzero as f64 / stats_large.total_digits as f64);
    println!("  Efficiency vs binary: {:.1}% fewer additions", 
             stats_large.efficiency_vs_binary * 100.0);
    
    // Performance test - JSF generation
    println!("\n=== JSF Generation Performance ===");
    let iterations = 10000;
    let start = Instant::now();
    
    for _ in 0..iterations {
        let _jsf = JsfIterator::new(s_test, h_test);
    }
    
    let elapsed = start.elapsed();
    println!("Generated {} JSFs in {:.3}ms", iterations, elapsed.as_secs_f64() * 1000.0);
    println!("Average JSF generation: {:.3}μs", elapsed.as_secs_f64() * 1_000_000.0 / iterations as f64);
    
    // Expected improvement calculation
    println!("\n=== Expected Performance Improvement ===");
    let binary_additions_per_scalar = stats_large.total_digits / 2;  // ~50% density
    let binary_total_additions = binary_additions_per_scalar * 2;    // Two scalars
    let jsf_additions = stats_large.total_nonzero;
    let improvement = binary_total_additions as f64 / jsf_additions as f64;
    
    println!("Binary method (estimated): {} point additions", binary_total_additions);
    println!("JSF method: {} point additions", jsf_additions);
    println!("Expected speedup: {:.2}x fewer point additions", improvement);
    
    println!("\n✅ JSF implementation test completed!");
}