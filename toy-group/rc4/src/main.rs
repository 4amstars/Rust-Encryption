
// RC4 stream cipher implementation—using KSA to initialize the state and PRGA to generate a keystream that’s XOR’d with your file bytes
// main.rs
use std::{
    env,
    fs::File,
    io::{self, Read, Write},
    process,
};

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
    let mut password = String::new();
    io::stdin().read_line(&mut password).unwrap();
    let key = password.trim().as_bytes();
    if key.is_empty() {
        eprintln!("Password cannot be empty");
        process::exit(1);
    }

    // Read input file
    let mut input_file = File::open(input_path).unwrap_or_else(|e| {
        eprintln!("Failed to open {}: {}", input_path, e);
        process::exit(1);
    });
    let mut data = Vec::new();
    input_file.read_to_end(&mut data).unwrap();

    // RC4 Key-Scheduling Algorithm (KSA)
    let mut s = [0u8; 256];
    for i in 0..=255u8 {
        s[i as usize] = i;
    }
    let mut j = 0u8;
    for i in 0..=255u8 {
        j = j
            .wrapping_add(s[i as usize])
            .wrapping_add(key[i as usize % key.len()]);
        s.swap(i as usize, j as usize);
    }

    // RC4 Pseudo-Random Generation Algorithm (PRGA) and XOR
    let mut i = 0u8;
    let mut j = 0u8;
    for byte in data.iter_mut() {
        i = i.wrapping_add(1);
        j = j.wrapping_add(s[i as usize]);
        s.swap(i as usize, j as usize);
        let idx = s[i as usize].wrapping_add(s[j as usize]);
        let k = s[idx as usize];
        *byte ^= k;
    }

    // Write output file
    let mut output_file = File::create(output_path).unwrap_or_else(|e| {
        eprintln!("Failed to create {}: {}", output_path, e);
        process::exit(1);
    });
    output_file.write_all(&data).unwrap();

    println!("{}ed {} → {}", mode, input_path, output_path);
}
