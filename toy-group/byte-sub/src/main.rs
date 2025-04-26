// main.rs
use std::{
    env,
    fs::File,
    io::{self, Read, Write},
    process,
};

fn derive_seed(key: &[u8]) -> u64 {
    let mut seed = 0u64;
    for &b in key {
        seed = seed.wrapping_mul(31).wrapping_add(b as u64);
    }
    seed
}

fn build_sboxes(key: &[u8]) -> ([u8; 256], [u8; 256]) {
    let mut sbox = [0u8; 256];
    for i in 0..256 {
        sbox[i] = i as u8;
    }
    let mut state = derive_seed(key);
    // Fisher–Yates shuffle with custom LCG
    for i in (1..256).rev() {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1);
        let j = ((state >> 33) as usize) % (i + 1);
        sbox.swap(i, j);
    }
    // build inverse S-box
    let mut inv = [0u8; 256];
    for (i, &v) in sbox.iter().enumerate() {
        inv[v as usize] = i as u8;
    }
    (sbox, inv)
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 || (args[1] != "encrypt" && args[1] != "decrypt") {
        eprintln!("Usage: {} [encrypt|decrypt] <input> <output>", args[0]);
        process::exit(1);
    }
    let mode = &args[1];
    let input_path = &args[2];
    let output_path = &args[3];

    // Prompt for password
    print!("Enter password: ");
    io::stdout().flush().unwrap();
    let mut pw = String::new();
    io::stdin().read_line(&mut pw).unwrap();
    let key = pw.trim().as_bytes();
    if key.is_empty() {
        eprintln!("Password cannot be empty");
        process::exit(1);
    }

    // Prepare S-box and inverse
    let (sbox, inv_sbox) = build_sboxes(key);

    // Read input
    let mut input = File::open(input_path).unwrap_or_else(|e| {
        eprintln!("Failed to open {}: {}", input_path, e);
        process::exit(1);
    });
    let mut data = Vec::new();
    input.read_to_end(&mut data).unwrap();

    // Substitute each byte
    for byte in data.iter_mut() {
        *byte = if mode == "encrypt" {
            sbox[*byte as usize]
        } else {
            inv_sbox[*byte as usize]
        };
    }

    // Write output
    let mut output = File::create(output_path).unwrap_or_else(|e| {
        eprintln!("Failed to create {}: {}", output_path, e);
        process::exit(1);
    });
    output.write_all(&data).unwrap();

    println!("{}ed {} → {}", mode, input_path, output_path);
}
