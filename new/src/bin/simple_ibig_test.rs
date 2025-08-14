// Simple test to see exactly where ibig-patched fails
// Run with: cargo run --bin simple_ibig_test --features="ibig-patched" --release

fn main() {
    println!("=== Simple ibig-patched test ===");

    // Just test basic OverflowingSub with small values
    use num_traits::ops::overflowing::OverflowingSub;

    let a = ibig_patched::UBig::from(3u32);
    let b = ibig_patched::UBig::from(10u32);

    println!("Testing: 3 - 10 with OverflowingSub...");
    println!("This should return (large_number, true) for overflow, not panic");

    let (result, overflow) = a.overflowing_sub(&b);

    println!("Result: {} (overflow: {})", result, overflow);
    println!("✅ If you see this message, OverflowingSub works for this case");
}
