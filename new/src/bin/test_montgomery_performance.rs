// Minimal test case to verify Montgomery arithmetic performance
// Run with: cargo run --bin test_montgomery_performance --features="fixed-bigint,fixed-bigint-u64,montgomery" --release

use std::time::Instant;

fn benchmark_modular_exponentiation() {
    println!("=== Montgomery vs Regular Modular Exponentiation Benchmark ===\n");

    // Use Ed25519 prime p = 2^255 - 19 for realistic test
    let p_bytes: [u8; 32] = [
        237, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127,
    ];

    // Large exponent similar to Ed25519 operations
    let exp_bytes: [u8; 32] = [
        235, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127,
    ];

    // Test base value
    let base_bytes: [u8; 32] = [
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,
        0xde, 0x0f,
    ];

    type BigInt = fixed_bigint::FixedUInt<u64, 8>;

    let p = BigInt::from_le_bytes(&p_bytes);
    let exp = BigInt::from_le_bytes(&exp_bytes);
    let base = BigInt::from_le_bytes(&base_bytes);

    const ITERATIONS: usize = 5;

    // Warmup
    for _ in 0..10 {
        let _ = modmath::basic_mod_exp(base, exp, p);
    }

    // Test regular modular exponentiation
    println!(
        "Testing regular modular exponentiation ({} iterations)...",
        ITERATIONS
    );
    let start = Instant::now();
    let mut regular_result = base;
    for _ in 0..ITERATIONS {
        regular_result = modmath::basic_mod_exp(base, exp, p);
    }
    let regular_time = start.elapsed();

    // Test Montgomery modular exponentiation
    println!(
        "Testing Montgomery modular exponentiation ({} iterations)...",
        ITERATIONS
    );
    let start = Instant::now();
    let mut montgomery_result = base;
    for _ in 0..ITERATIONS {
        montgomery_result = modmath::basic_montgomery_mod_exp(base, exp, p).unwrap();
    }
    let montgomery_time = start.elapsed();

    // Verify results are the same
    println!("\n=== Results ===");
    println!(
        "Regular result matches Montgomery: {}",
        regular_result == montgomery_result
    );

    println!("\n=== Performance Comparison ===");
    println!(
        "Regular mod_exp:   {:12.3}ms total, {:8.3}ms per op",
        regular_time.as_secs_f64() * 1000.0,
        regular_time.as_secs_f64() * 1000.0 / ITERATIONS as f64
    );
    println!(
        "Montgomery mod_exp: {:11.3}ms total, {:8.3}ms per op",
        montgomery_time.as_secs_f64() * 1000.0,
        montgomery_time.as_secs_f64() * 1000.0 / ITERATIONS as f64
    );

    let speedup = regular_time.as_secs_f64() / montgomery_time.as_secs_f64();
    println!(
        "Montgomery speedup: {:.2}x {}",
        speedup,
        if speedup > 1.0 { "faster" } else { "slower" }
    );

    if speedup < 1.5 {
        println!("\n⚠️  WARNING: Montgomery arithmetic should be significantly faster!");
        println!("   Expected speedup: 2-4x for large exponents");
        println!("   Actual speedup: {:.2}x", speedup);
        println!("   This suggests a performance issue in the Montgomery implementation.");
    } else {
        println!("\n✅ Montgomery arithmetic is working as expected");
    }
}

fn test_montgomery_parameter_overhead() {
    println!("\n\n=== Montgomery Parameter Computation Overhead Test ===\n");

    let p_bytes: [u8; 32] = [
        237, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127,
    ];

    type BigInt = fixed_bigint::FixedUInt<u64, 8>;
    let p = BigInt::from_le_bytes(&p_bytes);

    const PARAM_ITERATIONS: usize = 100;

    println!(
        "Testing Montgomery parameter computation ({} iterations)...",
        PARAM_ITERATIONS
    );
    let start = Instant::now();
    for _ in 0..PARAM_ITERATIONS {
        let _ = modmath::basic_compute_montgomery_params(p);
    }
    let param_time = start.elapsed();

    println!(
        "Parameter computation: {:.3}ms total, {:.6}ms per computation",
        param_time.as_secs_f64() * 1000.0,
        param_time.as_secs_f64() * 1000.0 / PARAM_ITERATIONS as f64
    );

    // Compare to single modular multiplication
    let base_bytes: [u8; 32] = [0x12; 32];
    let base = BigInt::from_le_bytes(&base_bytes);

    let start = Instant::now();
    for _ in 0..PARAM_ITERATIONS {
        let _ = modmath::basic_mod_mul(base, base, p);
    }
    let mul_time = start.elapsed();

    println!(
        "Single mod_mul:        {:.3}ms total, {:.6}ms per operation",
        mul_time.as_secs_f64() * 1000.0,
        mul_time.as_secs_f64() * 1000.0 / PARAM_ITERATIONS as f64
    );

    let overhead_ratio = param_time.as_secs_f64() / mul_time.as_secs_f64();
    println!(
        "Parameter overhead: {:.1}x cost of single multiplication",
        overhead_ratio
    );

    if overhead_ratio > 10.0 {
        println!("\n⚠️  WARNING: Montgomery parameter computation is very expensive!");
        println!("   For small numbers of operations, overhead may exceed benefits.");
    }
}

fn test_montgomery_methods() {
    println!("\n\n=== Montgomery N' Computation Methods Comparison ===\n");

    let p_bytes: [u8; 32] = [
        237, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127,
    ];

    type BigInt = fixed_bigint::FixedUInt<u64, 8>;
    let p = BigInt::from_le_bytes(&p_bytes);

    const METHOD_ITERATIONS: usize = 100;

    // Test each N' computation method
    use modmath::NPrimeMethod;

    let methods = [
        // Skip TrialSearch - it's O(R) and will be very slow for large R
        // (NPrimeMethod::TrialSearch, "Trial Search"),
        (NPrimeMethod::ExtendedEuclidean, "Extended Euclidean"),
        (NPrimeMethod::HenselsLifting, "Hensel's Lifting"),
    ];

    for (method, name) in &methods {
        println!(
            "Testing {} method ({} iterations)...",
            name, METHOD_ITERATIONS
        );
        let start = Instant::now();
        for _ in 0..METHOD_ITERATIONS {
            let _ = modmath::basic_compute_montgomery_params_with_method(p, *method);
        }
        let method_time = start.elapsed();

        println!(
            "{:20}: {:.3}ms total, {:.6}ms per computation",
            name,
            method_time.as_secs_f64() * 1000.0,
            method_time.as_secs_f64() * 1000.0 / METHOD_ITERATIONS as f64
        );
    }
}

fn main() {
    benchmark_modular_exponentiation();
    test_montgomery_parameter_overhead();
    test_montgomery_methods();

    println!("\n=== Summary ===");
    println!("If Montgomery arithmetic is working correctly:");
    println!("1. Montgomery mod_exp should be 2-4x faster than regular mod_exp");
    println!("2. Parameter overhead should be amortized over multiple operations");
    println!("3. Extended Euclidean should be fastest N' computation method");
    println!("\nIf any of these don't hold, there may be implementation issues.");
}
