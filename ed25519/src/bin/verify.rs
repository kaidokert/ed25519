fn main_inner<T>()
where
    T: ed25519_heapless::UnsignedModularInt
        + Copy
        + modmath::WideMul
        + modmath::CiosMontMul
        + num_traits::ops::overflowing::OverflowingAdd
        + num_traits::WrappingMul
        + num_traits::WrappingAdd
        + num_traits::WrappingSub,
    for<'a> &'a T: core::ops::BitAnd<Output = T>
        + core::ops::Add<&'a T, Output = T>
        + core::ops::Sub<&'a T, Output = T>
        + core::ops::Sub<T, Output = T>,
{
    let args: Vec<String> = std::env::args().collect();

    if args.len() != 4 {
        eprintln!("Usage: {} pkfile datafile sigfile", args[0]);
        std::process::exit(1);
    }

    let pk_path = &args[1];
    let data_path = &args[2];
    let sig_path = &args[3];

    let pk = std::fs::read(pk_path).unwrap_or_else(|e| {
        eprintln!("Error reading '{}': {}", pk_path, e);
        std::process::exit(1);
    });
    let data = std::fs::read(data_path).unwrap_or_else(|e| {
        eprintln!("Error reading '{}': {}", data_path, e);
        std::process::exit(1);
    });
    let signature = std::fs::read(sig_path).unwrap_or_else(|e| {
        eprintln!("Error reading '{}': {}", sig_path, e);
        std::process::exit(1);
    });

    let pk: [u8; 32] = pk.try_into().expect("public key is not 32 bytes");
    let signature: [u8; 64] = signature.try_into().expect("signature is not 64 bytes");

    let verification = ed25519_heapless::verify::<T>(pk, &data, signature);

    if verification {
        println!("ACCEPT");
    } else {
        println!("REJECT");
    }
}

fn main() {
    #[cfg(all(
        feature = "fixed-bigint",
        not(feature = "fixed-bigint-u64"),
        not(feature = "fixed-bigint-256"),
        not(feature = "fixed-bigint-u8")
    ))]
    main_inner::<fixed_bigint::FixedUInt<u32, 16>>();
    #[cfg(all(
        feature = "fixed-bigint",
        feature = "fixed-bigint-u64",
        not(feature = "fixed-bigint-256"),
        not(feature = "fixed-bigint-u8")
    ))]
    main_inner::<fixed_bigint::FixedUInt<u64, 8>>();
    #[cfg(all(
        feature = "fixed-bigint",
        feature = "fixed-bigint-256",
        not(feature = "fixed-bigint-u8")
    ))]
    main_inner::<fixed_bigint::FixedUInt<u64, 4>>();
    #[cfg(all(feature = "fixed-bigint", feature = "fixed-bigint-u8"))]
    main_inner::<fixed_bigint::FixedUInt<u8, 32>>();
}
