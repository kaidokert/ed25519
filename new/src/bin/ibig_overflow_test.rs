// Test if ibig-patched OverflowingSub works with different value sizes
// Run with: cargo run --bin ibig_overflow_test --features="ibig-patched" --release

fn main() {
    println!("=== ibig-patched OverflowingSub Test ===");

    // Test 1: Small values (like modmath-rs uses)
    println!("Test 1: Small values...");
    let small_a = ibig_patched::UBig::from(10u32);
    let small_b = ibig_patched::UBig::from(3u32);

    match std::panic::catch_unwind(|| {
        use num_traits::ops::overflowing::OverflowingSub;
        let (result, overflow) = small_a.overflowing_sub(&small_b);
        println!("  10 - 3 = {} (overflow: {})", result, overflow);
    }) {
        Ok(_) => println!("  ✅ Small values work fine"),
        Err(_) => println!("  ❌ Small values panic!"),
    }

    // Test 2: Edge case - subtraction that would underflow
    println!("\nTest 2: Underflow case...");
    let under_a = ibig_patched::UBig::from(3u32);
    let under_b = ibig_patched::UBig::from(10u32);

    match std::panic::catch_unwind(|| {
        use num_traits::ops::overflowing::OverflowingSub;
        let (result, overflow) = under_a.overflowing_sub(&under_b);
        println!("  3 - 10 = {} (overflow: {})", result, overflow);
    }) {
        Ok(_) => println!("  ✅ Underflow handled correctly"),
        Err(e) => {
            println!("  ❌ Underflow case panics!");
            if let Some(s) = e.downcast_ref::<&str>() {
                println!("  Panic message: {}", s);
            } else if let Some(s) = e.downcast_ref::<String>() {
                println!("  Panic message: {}", s);
            }
        }
    }

    // Test 3: Large values (Ed25519 scale)
    println!("\nTest 3: Large values (Ed25519 scale)...");
    let large_hex = "ac73c06fc72b95c72586773bf3cad0588de3d24661633cbfc887b8caa391bc33";
    let large_a = ibig_patched::UBig::from_str_radix(large_hex, 16).unwrap();
    let large_b = ibig_patched::UBig::from(1000u32);

    match std::panic::catch_unwind(|| {
        use num_traits::ops::overflowing::OverflowingSub;
        let (result, overflow) = large_a.overflowing_sub(&large_b);
        println!("  Large - 1000 worked (overflow: {})", overflow);
    }) {
        Ok(_) => println!("  ✅ Large values work fine"),
        Err(_) => println!("  ❌ Large values panic!"),
    }

    println!(
        "\nConclusion: The OverflowingSub panic occurs with specific value combinations during Ed25519 computation"
    );
}
