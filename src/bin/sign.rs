use std::io::Write;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    
    if args.len() < 4 || args.len() > 4 {
        eprintln!("Usage: {} prefix datafile sigfile\n Note : the file prefix.sk must exist on the current directory", args[0]);
        std::process::exit(1);
    }

    let filename = args[1].clone();
    let datafile = args[2].clone();
    let sigfile = args[3].clone();

    let sk_relative_path = filename.clone() + ".sk";

    if !std::fs::metadata(&sk_relative_path).is_ok() {
        eprintln!("File '{}' is not accessible.", sk_relative_path);
        std::process::exit(1);
    }

    if !std::fs::metadata(&datafile).is_ok() {
        eprintln!("File '{}' is not accessible.", datafile);
        std::process::exit(1);
    }

    let sk = std::fs::read(sk_relative_path).unwrap();
    let data = std::fs::read(datafile).unwrap();

    let secret: [u8; 32] = sk.try_into().expect("secret key is not 32 bytes");
    
    let sig = ed25519::ed25519::sign(secret, &data);
    let sign_file = std::fs::File::create(sigfile.clone());

    match sign_file {
        Ok(mut s) => {
            s.write_all(&sig).unwrap()
        },
        Err(e) => {
            eprintln!("Error creating sigfile : {}", e);
            std::process::exit(1);
        }
    }


}
