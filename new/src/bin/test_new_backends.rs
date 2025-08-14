// Quick test to verify that our new trait implementations work
// Run with: cargo run --bin test_new_backends --features="<backend>" --release

use std::time::Instant;

// Ed25519 test vectors (matching verify_baked.rs)
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
const ITERATIONS: usize = 3;

fn main() {
    println!("=== Ed25519 Backend Compatibility Test ===");

    let start = Instant::now();
    let mut successes = 0;

    for i in 0..ITERATIONS {
        let result = test_current_backend();
        if result {
            successes += 1;
        }
        println!(
            "Iteration {}: {}",
            i + 1,
            if result { "PASS" } else { "FAIL" }
        );
    }

    let total_time = start.elapsed();
    let avg_time_ms = total_time.as_secs_f64() * 1000.0 / ITERATIONS as f64;

    println!("\n=== Results ===");
    println!("Backend: {}", get_backend_name());
    println!("Mode: {}", get_mode_name());
    println!("Success rate: {}/{}", successes, ITERATIONS);
    println!("Total time: {:.3}ms", total_time.as_secs_f64() * 1000.0);
    println!("Average time: {:.3}ms", avg_time_ms);
    println!("Throughput: {:.1} ops/sec", 1000.0 / avg_time_ms);

    if successes == ITERATIONS {
        println!("✅ Backend working correctly");
    } else {
        println!("❌ Backend failed some tests");
        std::process::exit(1);
    }
}

fn test_current_backend() -> bool {
    #[cfg(all(feature = "fixed-bigint", not(feature = "fixed-bigint-u64")))]
    return ed25519n::strict::verify::<fixed_bigint::FixedUInt<u32, 16>>(
        PUBLIC_KEY, MESSAGE, SIGNATURE,
    );

    #[cfg(all(feature = "fixed-bigint", feature = "fixed-bigint-u64"))]
    return ed25519n::strict::verify::<fixed_bigint::FixedUInt<u64, 8>>(
        PUBLIC_KEY, MESSAGE, SIGNATURE,
    );

    #[cfg(feature = "bnum-patched")]
    return ed25519n::basic::verify::<bnum_patched::types::U512>(PUBLIC_KEY, MESSAGE, SIGNATURE);

    #[cfg(feature = "crypto-bigint-patched")]
    return ed25519n::constrained::verify::<crypto_bigint_patched::U512>(
        PUBLIC_KEY, MESSAGE, SIGNATURE,
    );

    #[cfg(feature = "num-bigint-patched")]
    return ed25519n::constrained::verify::<num_bigint_patched::BigUint>(
        PUBLIC_KEY, MESSAGE, SIGNATURE,
    );

    #[cfg(feature = "ibig-patched")]
    return ed25519n::constrained::verify::<ibig_patched::UBig>(PUBLIC_KEY, MESSAGE, SIGNATURE);

    #[cfg(feature = "bnum")]
    return ed25519n::constrained::verify::<bnum::types::U512>(PUBLIC_KEY, MESSAGE, SIGNATURE);

    // Default case if no backends are enabled
    false
}

fn get_backend_name() -> &'static str {
    #[cfg(all(feature = "fixed-bigint", not(feature = "fixed-bigint-u64")))]
    return "fixed-bigint (u32)";

    #[cfg(all(feature = "fixed-bigint", feature = "fixed-bigint-u64"))]
    return "fixed-bigint (u64)";

    #[cfg(feature = "bnum-patched")]
    return "bnum-patched";

    #[cfg(feature = "crypto-bigint-patched")]
    return "crypto-bigint-patched";

    #[cfg(feature = "num-bigint-patched")]
    return "num-bigint-patched";

    #[cfg(feature = "ibig-patched")]
    return "ibig-patched";

    #[cfg(feature = "bnum")]
    return "bnum";

    "unknown"
}

fn get_mode_name() -> &'static str {
    #[cfg(feature = "fixed-bigint")]
    return "strict";

    #[cfg(any(
        feature = "crypto-bigint-patched",
        feature = "num-bigint-patched",
        feature = "ibig-patched",
        feature = "bnum"
    ))]
    return "constrained";

    #[cfg(feature = "bnum-patched")]
    return "basic";

    "unknown"
}
