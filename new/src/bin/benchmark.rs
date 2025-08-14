use std::time::Instant;

fn benchmark_strict<T: ed25519n::BrigIntStrict>()
where
    for<'a> &'a T: core::ops::BitAnd<Output = T>
        + core::ops::Rem<&'a T, Output = T>
        + core::ops::Add<&'a T, Output = T>
        + core::ops::Sub<&'a T, Output = T>
        + core::ops::Mul<&'a T, Output = T>
        + core::ops::Div<&'a T, Output = T>
        + core::ops::Sub<T, Output = T>,
{
    let pk = [
        0x33, 0xbc, 0x91, 0xa3, 0xca, 0xb8, 0x87, 0xc8, 0xbf, 0x3c, 0x63, 0x61, 0x46, 0xd2, 0xe3,
        0x8d, 0x58, 0xd0, 0xca, 0xf3, 0x3b, 0x77, 0x86, 0x25, 0xc7, 0x95, 0x2b, 0xc7, 0x6f, 0xc0,
        0x73, 0xac,
    ];
    let signature = [
        0x2f, 0xec, 0x62, 0xdf, 0x49, 0x4f, 0xf5, 0x70, 0x5f, 0x5c, 0xee, 0x45, 0xbc, 0x5e, 0x89,
        0xc2, 0x32, 0xc1, 0x61, 0x88, 0x37, 0x87, 0xce, 0x50, 0xa2, 0x9b, 0xe8, 0x8c, 0xb1, 0x92,
        0xc8, 0x81, 0x25, 0x62, 0x74, 0xed, 0xd7, 0x67, 0x2a, 0xa5, 0x52, 0x79, 0x57, 0xeb, 0x0d,
        0xdc, 0x0e, 0x60, 0x95, 0x23, 0x74, 0x36, 0x22, 0x32, 0x85, 0xf6, 0xd9, 0x30, 0x6b, 0x96,
        0x63, 0x14, 0x86, 0x02,
    ];
    let d_str = "Hello world!\n";
    let data = d_str.as_bytes();

    const ITERATIONS: usize = 10;

    #[cfg(all(feature = "montgomery", feature = "montgomery-euclidean"))]
    println!(
        "=== STRICT Montgomery Arithmetic (Extended Euclidean) Benchmark ({} iterations) ===",
        ITERATIONS
    );
    #[cfg(all(feature = "montgomery", feature = "montgomery-hensels"))]
    println!(
        "=== STRICT Montgomery Arithmetic (Hensel's Lifting) Benchmark ({} iterations) ===",
        ITERATIONS
    );
    #[cfg(all(
        feature = "montgomery",
        not(feature = "montgomery-euclidean"),
        not(feature = "montgomery-hensels")
    ))]
    println!(
        "=== STRICT Montgomery Arithmetic (Extended Euclidean - default) Benchmark ({} iterations) ===",
        ITERATIONS
    );
    #[cfg(not(feature = "montgomery"))]
    println!(
        "=== STRICT Regular Modular Arithmetic Benchmark ({} iterations) ===",
        ITERATIONS
    );

    let mut total_time = std::time::Duration::new(0, 0);
    let mut successes = 0;

    for i in 0..ITERATIONS {
        let start = Instant::now();
        let verification = ed25519n::strict::verify::<T>(pk, data, signature);
        let duration = start.elapsed();

        total_time += duration;
        if verification {
            successes += 1;
        }

        if i % 10 == 0 {
            println!("Completed {} iterations...", i);
        }
    }

    let avg_time = total_time / ITERATIONS as u32;
    println!("Results:");
    println!("  Total time: {:?}", total_time);
    println!("  Average time per verification: {:?}", avg_time);
    println!(
        "  Average time per verification (ms): {:.3}",
        avg_time.as_secs_f64() * 1000.0
    );
    println!("  Successful verifications: {}/{}", successes, ITERATIONS);
    println!(
        "  Throughput: {:.1} verifications/second",
        ITERATIONS as f64 / total_time.as_secs_f64()
    );
}

fn benchmark_constrained<T: ed25519n::BrigIntConstrained>()
where
    for<'a> &'a T: core::ops::Rem<&'a T, Output = T> + core::ops::BitAnd<Output = T>,
{
    let pk = [
        0x33, 0xbc, 0x91, 0xa3, 0xca, 0xb8, 0x87, 0xc8, 0xbf, 0x3c, 0x63, 0x61, 0x46, 0xd2, 0xe3,
        0x8d, 0x58, 0xd0, 0xca, 0xf3, 0x3b, 0x77, 0x86, 0x25, 0xc7, 0x95, 0x2b, 0xc7, 0x6f, 0xc0,
        0x73, 0xac,
    ];
    let signature = [
        0x2f, 0xec, 0x62, 0xdf, 0x49, 0x4f, 0xf5, 0x70, 0x5f, 0x5c, 0xee, 0x45, 0xbc, 0x5e, 0x89,
        0xc2, 0x32, 0xc1, 0x61, 0x88, 0x37, 0x87, 0xce, 0x50, 0xa2, 0x9b, 0xe8, 0x8c, 0xb1, 0x92,
        0xc8, 0x81, 0x25, 0x62, 0x74, 0xed, 0xd7, 0x67, 0x2a, 0xa5, 0x52, 0x79, 0x57, 0xeb, 0x0d,
        0xdc, 0x0e, 0x60, 0x95, 0x23, 0x74, 0x36, 0x22, 0x32, 0x85, 0xf6, 0xd9, 0x30, 0x6b, 0x96,
        0x63, 0x14, 0x86, 0x02,
    ];
    let d_str = "Hello world!\n";
    let data = d_str.as_bytes();

    const ITERATIONS: usize = 10;

    #[cfg(all(feature = "montgomery", feature = "montgomery-euclidean"))]
    println!(
        "=== CONSTRAINED Montgomery Arithmetic (Extended Euclidean) Benchmark ({} iterations) ===",
        ITERATIONS
    );
    #[cfg(all(feature = "montgomery", feature = "montgomery-hensels"))]
    println!(
        "=== CONSTRAINED Montgomery Arithmetic (Hensel's Lifting) Benchmark ({} iterations) ===",
        ITERATIONS
    );
    #[cfg(all(
        feature = "montgomery",
        not(feature = "montgomery-euclidean"),
        not(feature = "montgomery-hensels")
    ))]
    println!(
        "=== CONSTRAINED Montgomery Arithmetic (Extended Euclidean - default) Benchmark ({} iterations) ===",
        ITERATIONS
    );
    #[cfg(not(feature = "montgomery"))]
    println!(
        "=== CONSTRAINED Regular Modular Arithmetic Benchmark ({} iterations) ===",
        ITERATIONS
    );

    let mut total_time = std::time::Duration::new(0, 0);
    let mut successes = 0;

    for i in 0..ITERATIONS {
        let start = Instant::now();
        let verification = ed25519n::constrained::verify::<T>(pk, data, signature);
        let duration = start.elapsed();

        total_time += duration;
        if verification {
            successes += 1;
        }

        if i % 10 == 0 {
            println!("Completed {} iterations...", i);
        }
    }

    let avg_time = total_time / ITERATIONS as u32;
    println!("Results:");
    println!("  Total time: {:?}", total_time);
    println!("  Average time per verification: {:?}", avg_time);
    println!(
        "  Average time per verification (ms): {:.3}",
        avg_time.as_secs_f64() * 1000.0
    );
    println!("  Successful verifications: {}/{}", successes, ITERATIONS);
    println!(
        "  Throughput: {:.1} verifications/second",
        ITERATIONS as f64 / total_time.as_secs_f64()
    );
}

fn benchmark_basic<T: ed25519n::basic::BrigIntBasic>() {
    let pk = [
        0x33, 0xbc, 0x91, 0xa3, 0xca, 0xb8, 0x87, 0xc8, 0xbf, 0x3c, 0x63, 0x61, 0x46, 0xd2, 0xe3,
        0x8d, 0x58, 0xd0, 0xca, 0xf3, 0x3b, 0x77, 0x86, 0x25, 0xc7, 0x95, 0x2b, 0xc7, 0x6f, 0xc0,
        0x73, 0xac,
    ];
    let signature = [
        0x2f, 0xec, 0x62, 0xdf, 0x49, 0x4f, 0xf5, 0x70, 0x5f, 0x5c, 0xee, 0x45, 0xbc, 0x5e, 0x89,
        0xc2, 0x32, 0xc1, 0x61, 0x88, 0x37, 0x87, 0xce, 0x50, 0xa2, 0x9b, 0xe8, 0x8c, 0xb1, 0x92,
        0xc8, 0x81, 0x25, 0x62, 0x74, 0xed, 0xd7, 0x67, 0x2a, 0xa5, 0x52, 0x79, 0x57, 0xeb, 0x0d,
        0xdc, 0x0e, 0x60, 0x95, 0x23, 0x74, 0x36, 0x22, 0x32, 0x85, 0xf6, 0xd9, 0x30, 0x6b, 0x96,
        0x63, 0x14, 0x86, 0x02,
    ];
    let d_str = "Hello world!\n";
    let data = d_str.as_bytes();

    const ITERATIONS: usize = 10;

    #[cfg(all(feature = "montgomery", feature = "montgomery-euclidean"))]
    println!(
        "=== BASIC Montgomery Arithmetic (Extended Euclidean) Benchmark ({} iterations) ===",
        ITERATIONS
    );
    #[cfg(all(feature = "montgomery", feature = "montgomery-hensels"))]
    println!(
        "=== BASIC Montgomery Arithmetic (Hensel's Lifting) Benchmark ({} iterations) ===",
        ITERATIONS
    );
    #[cfg(all(
        feature = "montgomery",
        not(feature = "montgomery-euclidean"),
        not(feature = "montgomery-hensels")
    ))]
    println!(
        "=== BASIC Montgomery Arithmetic (Extended Euclidean - default) Benchmark ({} iterations) ===",
        ITERATIONS
    );
    #[cfg(not(feature = "montgomery"))]
    println!(
        "=== BASIC Regular Modular Arithmetic Benchmark ({} iterations) ===",
        ITERATIONS
    );

    let mut total_time = std::time::Duration::new(0, 0);
    let mut successes = 0;

    for i in 0..ITERATIONS {
        let start = std::time::Instant::now();
        let verification = ed25519n::basic::verify::<T>(pk, data, signature);
        let duration = start.elapsed();

        total_time += duration;
        if verification {
            successes += 1;
        }

        if i % 10 == 0 {
            println!("Completed {} iterations...", i);
        }
    }

    let avg_time = total_time / ITERATIONS as u32;
    println!("Results:");
    println!("  Total time: {:?}", total_time);
    println!("  Average time per verification: {:?}", avg_time);
    println!(
        "  Average time per verification (ms): {:.3}",
        avg_time.as_secs_f64() * 1000.0
    );
    println!("  Successful verifications: {}/{}", successes, ITERATIONS);
    println!(
        "  Throughput: {:.1} verifications/second",
        ITERATIONS as f64 / total_time.as_secs_f64()
    );
}

fn main() {
    println!("=== ED25519 BASIC IMPLEMENTATION BENCHMARK ===");
    println!("Comparing all basic implementations with 64-bit backends (10 iterations each)\n");

    // fixed-bigint u64 (best performer from previous tests)
    #[cfg(feature = "fixed-bigint")]
    {
        println!("=== BASIC MODE: fixed-bigint FixedUInt<u64, 8> ===");
        benchmark_basic::<fixed_bigint::FixedUInt<u64, 8>>();
        println!();
    }

    // bnum_patched
    #[cfg(feature = "bnum-patched")]
    {
        println!("=== BASIC MODE: bnum_patched U512 ===");
        benchmark_basic::<bnum_patched::types::U512>();
        println!();
    }

    // crypto-bigint_patched
    #[cfg(feature = "crypto-bigint-patched")]
    {
        println!("=== BASIC MODE: crypto-bigint_patched U512 ===");
        benchmark_basic::<crypto_bigint_patched::U512>();
        println!();
    }

    println!("=== BENCHMARK COMPLETE ===");
}
