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

    // Prompt for shift amount
    print!("Enter shift amount (0-255): ");
    io::stdout().flush().unwrap();
    let mut shift_str = String::new();
    io::stdin().read_line(&mut shift_str).unwrap();
    let shift: u8 = match shift_str.trim().parse() {
        Ok(n) => n,
        Err(_) => {
            eprintln!("Invalid shift value");
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

    // Apply Caesar shift
    for byte in data.iter_mut() {
        *byte = if mode == "encrypt" {
            byte.wrapping_add(shift)
        } else {
            byte.wrapping_sub(shift)
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
