// Generic benchmark that works with all bigint backends
// Run with: cargo run --bin generic_benchmark --features="<backend>" --release

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
const ITERATIONS: usize = 5;

fn benchmark_backend(backend_name: &str, mode: &str) -> Option<(f64, f64)> {
    println!("=== {} ({} mode) ===", backend_name, mode);

    // Warmup
    for _ in 0..2 {
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
                PUBLIC_KEY, MESSAGE, SIGNATURE,
            );
            #[cfg(not(feature = "fixed-bigint-u64"))]
            let _ = ed25519n::strict::verify::<fixed_bigint::FixedUInt<u32, 16>>(
                PUBLIC_KEY, MESSAGE, SIGNATURE,
            );
        }

        #[cfg(feature = "bnum")]
        let _ = ed25519n::basic::verify::<bnum::types::U512>(PUBLIC_KEY, MESSAGE, SIGNATURE);

        #[cfg(feature = "bnum-patched")]
        let _ =
            ed25519n::basic::verify::<bnum_patched::types::U512>(PUBLIC_KEY, MESSAGE, SIGNATURE);

        #[cfg(feature = "crypto-bigint-patched")]
        let _ = ed25519n::constrained::verify::<crypto_bigint_patched::U512>(
            PUBLIC_KEY, MESSAGE, SIGNATURE,
        );

        #[cfg(feature = "num-bigint-patched")]
        let _ = ed25519n::constrained::verify::<num_bigint_patched::BigUint>(
            PUBLIC_KEY, MESSAGE, SIGNATURE,
        );

        #[cfg(feature = "ibig-patched")]
        let _ = ed25519n::constrained::verify::<ibig_patched::UBig>(PUBLIC_KEY, MESSAGE, SIGNATURE);

        #[cfg(feature = "num-bigint-patched")]
        let _ = ed25519n::constrained::verify::<num_bigint_patched::BigUint>(
            PUBLIC_KEY, MESSAGE, SIGNATURE,
        );

        #[cfg(feature = "bnum")]
        let _ = ed25519n::constrained::verify::<bnum::types::U512>(PUBLIC_KEY, MESSAGE, SIGNATURE);
    }

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
                        PUBLIC_KEY, MESSAGE, SIGNATURE,
                    )
                }
                #[cfg(not(feature = "fixed-bigint-u64"))]
                {
                    ed25519n::strict::verify::<fixed_bigint::FixedUInt<u32, 16>>(
                        PUBLIC_KEY, MESSAGE, SIGNATURE,
                    )
                }
            }

            #[cfg(feature = "bnum")]
            {
                ed25519n::basic::verify::<bnum::types::U512>(PUBLIC_KEY, MESSAGE, SIGNATURE)
            }

            #[cfg(feature = "bnum-patched")]
            {
                ed25519n::basic::verify::<bnum_patched::types::U512>(PUBLIC_KEY, MESSAGE, SIGNATURE)
            }

            #[cfg(feature = "crypto-bigint-patched")]
            {
                ed25519n::constrained::verify::<crypto_bigint_patched::U512>(
                    PUBLIC_KEY, MESSAGE, SIGNATURE,
                )
            }

            #[cfg(feature = "num-bigint-patched")]
            {
                ed25519n::constrained::verify::<num_bigint_patched::BigUint>(
                    PUBLIC_KEY, MESSAGE, SIGNATURE,
                )
            }

            #[cfg(feature = "ibig-patched")]
            {
                ed25519n::constrained::verify::<ibig_patched::UBig>(PUBLIC_KEY, MESSAGE, SIGNATURE)
            }

            #[cfg(feature = "num-bigint-patched")]
            {
                ed25519n::constrained::verify::<num_bigint_patched::BigUint>(
                    PUBLIC_KEY, MESSAGE, SIGNATURE,
                )
            }

            #[cfg(feature = "bnum")]
            {
                ed25519n::constrained::verify::<bnum::types::U512>(PUBLIC_KEY, MESSAGE, SIGNATURE)
            }
        };

        if result {
            success_count += 1;
        }
    }

    let total_time = start.elapsed();
    let avg_time_ms = total_time.as_secs_f64() * 1000.0 / ITERATIONS as f64;
    let ops_per_sec = 1000.0 / avg_time_ms;

    println!("Results:");
    println!("  Total time: {:.3}ms", total_time.as_secs_f64() * 1000.0);
    println!("  Average time: {:.3}ms", avg_time_ms);
    println!("  Throughput: {:.1} ops/sec", ops_per_sec);
    println!("  Success rate: {}/{}", success_count, ITERATIONS);
    println!();

    if success_count == ITERATIONS {
        Some((avg_time_ms, ops_per_sec))
    } else {
        println!("⚠️ Some verifications failed!");
        None
    }
}

fn main() {
    println!("=== Ed25519 Generic Performance Benchmark ===");
    println!();

    // Detect current configuration
    let (backend, mode) = {
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
                ("fixed-bigint (u64)", "strict")
            }
            #[cfg(not(feature = "fixed-bigint-u64"))]
            {
                ("fixed-bigint (u32)", "strict")
            }
        }

        #[cfg(feature = "bnum")]
        {
            ("bnum", "basic")
        }

        #[cfg(feature = "bnum-patched")]
        {
            ("bnum-patched", "basic")
        }

        #[cfg(feature = "crypto-bigint-patched")]
        {
            ("crypto-bigint-patched", "constrained")
        }

        #[cfg(feature = "num-bigint-patched")]
        {
            ("num-bigint-patched", "constrained")
        }

        #[cfg(feature = "ibig-patched")]
        {
            ("ibig-patched", "constrained")
        }

        #[cfg(feature = "num-bigint-patched")]
        {
            ("num-bigint-patched", "constrained")
        }

        #[cfg(feature = "bnum")]
        {
            ("bnum", "constrained")
        }
    };

    if let Some((avg_time, ops_sec)) = benchmark_backend(backend, mode) {
        println!("=== Summary ===");
        println!("Backend: {}", backend);
        println!("Mode: {}", mode);
        println!("Average time: {:.3}ms", avg_time);
        println!("Throughput: {:.1} ops/sec", ops_sec);

        // Performance assessment
        if avg_time < 20.0 {
            println!("🚀 Excellent performance!");
        } else if avg_time < 50.0 {
            println!("✅ Good performance");
        } else if avg_time < 100.0 {
            println!("⚠️ Moderate performance");
        } else {
            println!("🐌 Slow performance");
        }
    } else {
        println!("❌ Benchmark failed");
        std::process::exit(1);
    }
}
