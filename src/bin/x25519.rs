use x22519::hex;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    
    if args.len() < 2 || args.len() > 3 {
        eprintln!("Usage: x25519 <m> [<u>]");
        std::process::exit(1);
    }

    let m = hex::decode_scalar25519(&args[1]);
    //let m = hex::decode_scalar25519(&"a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4".to_string());

    let u = if args.len() == 3 {
        hex::decode_ucoordinate(&args[2])
    } else {
        hex::decode_ucoordinate(&"0900000000000000000000000000000000000000000000000000000000000000".to_string())
    };
    
    dbg!(m, u);
    
    let p = &x22519::elliptic::P.clone();
    let a24:&bnum::types::I512 = &(x22519::elliptic::A24.clone());

    let result = x22519::elliptic::ladder(&m, &u, p, a24);
    let result = ((&result.0).rem_euclid(*p) * (x22519::mathutils::modinverse(result.1, p.clone()).expect("p not prime")).rem_euclid(*p)).rem_euclid(*p);
    //let result = String::from(result.to_radix_be(16).1.to_ascii_lowercase());
    let result = result.to_radix_le(16);
    for i in 0..result.len()/2 {
        print!("{:x}{:x}", result[2*i + 1], result[2*i])
    }

}
