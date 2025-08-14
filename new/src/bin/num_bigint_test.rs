// Minimal test for num-bigint-patched backend
// Run with: cargo run --bin num_bigint_test --features="num-bigint-patched" --release

// Ed25519 test vectors
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
    println!("=== num-bigint-patched Ed25519 Test ===");

    // Test strict mode (should work according to modmath compatibility)
    println!("Testing STRICT mode...");
    let strict_result =
        ed25519n::strict::verify::<num_bigint_patched::BigUint>(PUBLIC_KEY, MESSAGE, SIGNATURE);
    println!(
        "STRICT result: {}",
        if strict_result {
            "✅ PASS"
        } else {
            "❌ FAIL"
        }
    );

    // Test constrained mode (should work according to modmath compatibility)
    println!("Testing CONSTRAINED mode...");
    let constrained_result = ed25519n::constrained::verify::<num_bigint_patched::BigUint>(
        PUBLIC_KEY, MESSAGE, SIGNATURE,
    );
    println!(
        "CONSTRAINED result: {}",
        if constrained_result {
            "✅ PASS"
        } else {
            "❌ FAIL"
        }
    );

    // Test basic mode (should NOT work - heap allocated, no Copy trait)
    println!("Testing BASIC mode...");
    println!("BASIC result: ❌ SKIPPED (no Copy trait for heap-allocated types)");

    if strict_result && constrained_result {
        println!("\n🎉 num-bigint-patched working in 2/2 expected modes!");
    } else {
        println!("\n❌ num-bigint-patched has issues");
    }
}
