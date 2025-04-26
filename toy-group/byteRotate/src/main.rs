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

    // Prompt for number of bits to rotate (0–7)
    print!("Enter rotate amount (0–7): ");
    io::stdout().flush().unwrap();
    let mut bits_str = String::new();
    io::stdin().read_line(&mut bits_str).unwrap();
    let bits: u32 = match bits_str.trim().parse() {
        Ok(n) if n <= 7 => n,
        _ => {
            eprintln!("Invalid rotate amount");
            process::exit(1);
        }
    };

    // Read input file
    let mut input_file = File::open(input_path).unwrap_or_else(|e| {
        eprintln!("Failed to open {}: {}", input_path, e);
        process::exit(1);
    });
    let mut data = Vec::new();
    input_file.read_to_end(&mut data).unwrap();

    // Rotate each byte
    for byte in data.iter_mut() {
        *byte = if mode == "encrypt" {
            byte.rotate_left(bits)
        } else {
            byte.rotate_right(bits)
        };
    }

    // Write output file
    let mut output_file = File::create(output_path).unwrap_or_else(|e| {
        eprintln!("Failed to create {}: {}", output_path, e);
        process::exit(1);
    });
    output_file.write_all(&data).unwrap();

    println!("{}ed {} → {}", mode, input_path, output_path);
}
