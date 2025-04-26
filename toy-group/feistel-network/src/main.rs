// main.rs
use std::{
    env,
    fs::File,
    io::{self, Read, Write},
    process,
};

const ROUND_COUNT: usize = 16;

fn round_function(x: u32, k: u32) -> u32 {
    x.wrapping_add(k).rotate_left(5)
}

fn feistel_encrypt_block(block: &mut [u8; 8], subkeys: &[u32; ROUND_COUNT]) {
    let mut l = u32::from_be_bytes([block[0], block[1], block[2], block[3]]);
    let mut r = u32::from_be_bytes([block[4], block[5], block[6], block[7]]);
    for i in 0..ROUND_COUNT {
        let new_l = r;
        let new_r = l ^ round_function(r, subkeys[i]);
        l = new_l;
        r = new_r;
    }
    let lb = l.to_be_bytes();
    let rb = r.to_be_bytes();
    block[0..4].copy_from_slice(&lb);
    block[4..8].copy_from_slice(&rb);
}

fn feistel_decrypt_block(block: &mut [u8; 8], subkeys: &[u32; ROUND_COUNT]) {
    let mut l = u32::from_be_bytes([block[0], block[1], block[2], block[3]]);
    let mut r = u32::from_be_bytes([block[4], block[5], block[6], block[7]]);
    for i in (0..ROUND_COUNT).rev() {
        let new_r = l;
        let new_l = r ^ round_function(l, subkeys[i]);
        l = new_l;
        r = new_r;
    }
    let lb = l.to_be_bytes();
    let rb = r.to_be_bytes();
    block[0..4].copy_from_slice(&lb);
    block[4..8].copy_from_slice(&rb);
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
    let key_bytes = pw.trim().as_bytes();
    if key_bytes.is_empty() {
        eprintln!("Password cannot be empty");
        process::exit(1);
    }

    // Derive 16 u32 subkeys from password
    let mut kbuf = Vec::with_capacity(4 * ROUND_COUNT);
    for i in 0..(4 * ROUND_COUNT) {
        kbuf.push(key_bytes[i % key_bytes.len()]);
    }
    let mut subkeys = [0u32; ROUND_COUNT];
    for i in 0..ROUND_COUNT {
        let idx = 4 * i;
        subkeys[i] = u32::from_be_bytes([
            kbuf[idx],
            kbuf[idx + 1],
            kbuf[idx + 2],
            kbuf[idx + 3],
        ]);
    }

    // Read & pad file
    let mut file = File::open(input_path).unwrap_or_else(|e| {
        eprintln!("Failed to open {}: {}", input_path, e);
        process::exit(1);
    });
    let mut data = Vec::new();
    file.read_to_end(&mut data).unwrap();
    let pad = (8 - (data.len() % 8)) % 8;
    data.extend(std::iter::repeat(0).take(pad));

    // Process each 8‑byte block
    for chunk in data.chunks_mut(8) {
        let mut block = [0u8; 8];
        block.copy_from_slice(chunk);
        if mode == "encrypt" {
            feistel_encrypt_block(&mut block, &subkeys);
        } else {
            feistel_decrypt_block(&mut block, &subkeys);
        }
        chunk.copy_from_slice(&block);
    }

    // Write output
    let mut out = File::create(output_path).unwrap_or_else(|e| {
        eprintln!("Failed to create {}: {}", output_path, e);
        process::exit(1);
    });
    out.write_all(&data).unwrap();

    println!("{}ed {} → {}", mode, input_path, output_path);
}
