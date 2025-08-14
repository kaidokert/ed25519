// Comprehensive benchmark across all bignum implementations and arithmetic modes
// Run with: cargo run --bin benchmark_comprehensive --features="..." --release

use std::time::Instant;

fn benchmark_ed25519_verify() {
    println!("=== Ed25519 Signature Verification Benchmark ===\n");

    // Sample signature data from Ed25519 test vectors
    let public_key_bytes = [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07,
        0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07,
        0x51, 0x1a,
    ];

    let signature_bytes = [
        0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82,
        0x8a, 0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49,
        0x01, 0x55, 0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e, 0x39, 0x70, 0x1c,
        0xf9, 0xb4, 0x6b, 0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24, 0x65, 0x51, 0x41, 0x43,
        0x8e, 0x7a, 0x10, 0x0b,
    ];

    let message = b"abc";

    const ITERATIONS: usize = 10;

    // Warmup
    for _ in 0..5 {
        #[cfg(all(
            feature = "fixed-bigint",
            not(any(
                feature = "num-bigint",
                feature = "bnum",
                feature = "crypto-bigint",
                feature = "ibig"
            ))
        ))]
        {
            #[cfg(feature = "fixed-bigint-u64")]
            let _ = ed25519n::strict::verify::<fixed_bigint::FixedUInt<u64, 8>>(
                public_key_bytes,
                message,
                signature_bytes,
            );
            #[cfg(not(feature = "fixed-bigint-u64"))]
            let _ = ed25519n::strict::verify::<fixed_bigint::FixedUInt<u32, 16>>(
                public_key_bytes,
                message,
                signature_bytes,
            );
        }

        #[cfg(any(feature = "num-bigint", feature = "num-bigint-patched"))]
        let _ = ed25519n::basic::verify(public_key_bytes, message, signature_bytes);

        #[cfg(any(feature = "bnum", feature = "bnum-patched"))]
        let _ = ed25519n::basic::verify(public_key_bytes, message, signature_bytes);

        #[cfg(any(feature = "crypto-bigint", feature = "crypto-bigint-patched"))]
        let _ = ed25519n::constrained::verify(public_key_bytes, message, signature_bytes);

        #[cfg(any(feature = "ibig", feature = "ibig-patched"))]
        let _ = ed25519n::basic::verify(public_key_bytes, message, signature_bytes);
    }

    // Benchmark
    println!("Running {} iterations...", ITERATIONS);
    let start = Instant::now();

    let mut success_count = 0;
    for _ in 0..ITERATIONS {
        let result = {
            #[cfg(all(
                feature = "fixed-bigint",
                not(any(
                    feature = "num-bigint",
                    feature = "bnum",
                    feature = "crypto-bigint",
                    feature = "ibig"
                ))
            ))]
            {
                #[cfg(feature = "fixed-bigint-u64")]
                {
                    ed25519n::strict::verify::<fixed_bigint::FixedUInt<u64, 8>>(
                        public_key_bytes,
                        message,
                        signature_bytes,
                    )
                }
                #[cfg(not(feature = "fixed-bigint-u64"))]
                {
                    ed25519n::strict::verify::<fixed_bigint::FixedUInt<u32, 16>>(
                        public_key_bytes,
                        message,
                        signature_bytes,
                    )
                }
            }

            #[cfg(any(feature = "num-bigint", feature = "num-bigint-patched"))]
            {
                ed25519n::basic::verify(public_key_bytes, message, signature_bytes)
            }

            #[cfg(any(feature = "bnum", feature = "bnum-patched"))]
            {
                ed25519n::basic::verify(public_key_bytes, message, signature_bytes)
            }

            #[cfg(any(feature = "crypto-bigint", feature = "crypto-bigint-patched"))]
            {
                ed25519n::constrained::verify(public_key_bytes, message, signature_bytes)
            }

            #[cfg(any(feature = "ibig", feature = "ibig-patched"))]
            {
                ed25519n::basic::verify(public_key_bytes, message, signature_bytes)
            }
        };

        if result {
            success_count += 1;
        }
    }

    let total_time = start.elapsed();
    let avg_time = total_time / ITERATIONS as u32;

    println!("Results:");
    println!("  Total time: {:.3}ms", total_time.as_secs_f64() * 1000.0);
    println!("  Average time: {:.3}ms", avg_time.as_secs_f64() * 1000.0);
    println!("  Throughput: {:.1} ops/sec", 1.0 / avg_time.as_secs_f64());
    println!("  Success rate: {}/{}", success_count, ITERATIONS);
    println!();
}

fn main() {
    // Print current configuration
    println!("=== Configuration ===");

    #[cfg(feature = "fixed-bigint")]
    {
        #[cfg(feature = "fixed-bigint-u64")]
        println!("BigInt Backend: fixed-bigint (u64)");
        #[cfg(not(feature = "fixed-bigint-u64"))]
        println!("BigInt Backend: fixed-bigint (u32)");
    }

    #[cfg(feature = "num-bigint")]
    println!("BigInt Backend: num-bigint");

    #[cfg(feature = "num-bigint-patched")]
    println!("BigInt Backend: num-bigint-patched");

    #[cfg(feature = "bnum")]
    println!("BigInt Backend: bnum");

    #[cfg(feature = "bnum-patched")]
    println!("BigInt Backend: bnum-patched");

    #[cfg(feature = "crypto-bigint")]
    println!("BigInt Backend: crypto-bigint");

    #[cfg(feature = "crypto-bigint-patched")]
    println!("BigInt Backend: crypto-bigint-patched");

    #[cfg(feature = "ibig")]
    println!("BigInt Backend: ibig");

    #[cfg(feature = "ibig-patched")]
    println!("BigInt Backend: ibig-patched");

    // Determine arithmetic mode
    #[cfg(all(
        feature = "fixed-bigint",
        not(any(
            feature = "num-bigint",
            feature = "bnum",
            feature = "crypto-bigint",
            feature = "ibig"
        ))
    ))]
    {
        #[cfg(feature = "montgomery")]
        println!("Arithmetic Mode: strict (with Montgomery)");
        #[cfg(not(feature = "montgomery"))]
        println!("Arithmetic Mode: strict");
    }

    #[cfg(feature = "num-bigint")]
    println!("Arithmetic Mode: basic");

    #[cfg(feature = "bnum")]
    println!("Arithmetic Mode: basic");

    #[cfg(feature = "crypto-bigint")]
    println!("Arithmetic Mode: constrained");

    #[cfg(feature = "ibig")]
    println!("Arithmetic Mode: basic");

    println!();

    benchmark_ed25519_verify();
}
