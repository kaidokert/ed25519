use std::io::Write;

use rand::Rng;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    
    if args.len() < 2 || args.len() > 2 {
        eprintln!("Usage: {} prefix", args[0]);
        std::process::exit(1);
    }

    let filename = args[1].clone();


    let random_32_bytes = rand::thread_rng().gen::<[u8; 32]>();

    // The private key will be the random 32 bytes
    let private_key = random_32_bytes.clone();
    let public_key = ed25519::hex::secret_to_public(private_key);

    println!("Private key: {}", private_key.len());
    // The public key : sha512 and keep 32 bytes of the private key
    for i in 0..32 {
        print!("{:02x}", private_key[i]);
    }

    let sk_relative_path = filename.clone() + ".sk";
    let pk_relative_path = filename.clone() + ".pk";

    // Verify we can create the files
    let sk_file = std::fs::File::create(sk_relative_path.clone());
    let pk_file = std::fs::File::create(pk_relative_path.clone());

    match sk_file {
        Ok(mut s) => {
            s.write_all(&private_key).unwrap()
        },
        Err(e) => {
            eprintln!("Error creating private key file: {}", e);
            std::process::exit(1);
        }
    }

    match pk_file {
        Ok(mut p) => {
            p.write_all(&public_key[0..32]).unwrap();
        },

        Err(e) => {
            eprintln!("Error creating public key file: {}", e);
            std::process::exit(1);
        }
    }
}
