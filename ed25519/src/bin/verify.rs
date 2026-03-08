fn main() {
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

    let verification =
        ed25519_heapless::verify::<fixed_bigint::FixedUInt<u32, 16>>(pk, &data, signature);

    if verification {
        println!("ACCEPT");
    } else {
        println!("REJECT");
    }
}
