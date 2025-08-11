fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 4 || args.len() > 4 {
        eprintln!("Usage: {} pkfile datafile sigfile", args[0]);
        std::process::exit(1);
    }

    let filename = args[1].clone();
    let datafile = args[2].clone();
    let sigfile = args[3].clone();

    let pk_relative_path = filename.clone();

    if !std::fs::metadata(&pk_relative_path).is_ok() {
        eprintln!("File '{}' is not accessible.", pk_relative_path);
        std::process::exit(1);
    }

    if !std::fs::metadata(&datafile).is_ok() {
        eprintln!("File '{}' is not accessible.", datafile);
        std::process::exit(1);
    }

    if !std::fs::metadata(&sigfile).is_ok() {
        eprintln!("File '{}' is not accessible.", datafile);
        std::process::exit(1);
    }

    let pk = std::fs::read(pk_relative_path).unwrap();
    let data = std::fs::read(datafile).unwrap();
    let signature = std::fs::read(sigfile).unwrap();

    let pk: [u8; 32] = pk.try_into().expect("public key is not 32 bytes");
    let signature: [u8; 64] = signature.try_into().expect("signature is not 64 bytes");

    let verification = ed25519::ed25519::verify(pk, &data, signature);

    if verification {
        println!("ACCEPT");
    } else {
        println!("REJECT");
    }
}
