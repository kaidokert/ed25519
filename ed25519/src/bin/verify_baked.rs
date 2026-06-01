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
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Debug)
        .format_timestamp_micros()
        .init();

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
    let verification = ed25519_heapless::verify::<T>(pk, data, signature);

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
