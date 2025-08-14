// Test ibig-patched with simple values like modmath-rs uses
// Run with: cargo run --bin ibig_simple_test --features="ibig-patched" --release

// Import from our dependency
extern crate modmath;

fn main() {
    println!("=== ibig-patched Simple Test (like modmath-rs) ===");

    // Test with small values like modmath-rs uses: pow(5,3,13) = 8
    println!("Testing small values (5^3 mod 13 = 8)...");

    let a = ibig_patched::UBig::from(5u8);
    let b = ibig_patched::UBig::from(3u8);
    let m = ibig_patched::UBig::from(13u8);
    let expected = ibig_patched::UBig::from(8u8);

    // Test strict_mod_exp
    println!("Testing strict_mod_exp...");
    let result_strict = modmath::strict_mod_exp(a.clone(), &b, &m);
    let strict_ok = result_strict == expected;
    println!(
        "strict_mod_exp result: {} (expected 8) -> {}",
        result_strict,
        if strict_ok { "✅" } else { "❌" }
    );

    // Test constrained_mod_exp
    println!("Testing constrained_mod_exp...");
    let result_constrained = modmath::constrained_mod_exp(a.clone(), &b, &m);
    let constrained_ok = result_constrained == expected;
    println!(
        "constrained_mod_exp result: {} (expected 8) -> {}",
        result_constrained,
        if constrained_ok { "✅" } else { "❌" }
    );

    if strict_ok && constrained_ok {
        println!("\n✅ ibig-patched works fine with SMALL values!");
        println!(
            "The issue is likely with LARGE Ed25519 values causing overflow in OverflowingSub"
        );
    } else {
        println!("\n❌ ibig-patched fails even with small values");
    }
}
