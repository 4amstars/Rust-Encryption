// main.rs
use std::{
    env,
    fs::File,
    io::{self, Read, Write},
    process,
};

const DELTA: u32 = 0x9E3779B9;
const ROUNDS: usize = 32;

fn tea_encrypt_block(v: &mut [u32; 2], k: &[u32; 4]) {
    let (mut v0, mut v1) = (v[0], v[1]);
    let mut sum = 0u32;
    for _ in 0..ROUNDS {
        sum = sum.wrapping_add(DELTA);
        v0 = v0.wrapping_add(
            ((v1 << 4) ^ (v1 >> 5))
                .wrapping_add(v1)
                ^ (sum.wrapping_add(k[(sum & 3) as usize])),
        );
        v1 = v1.wrapping_add(
            ((v0 << 4) ^ (v0 >> 5))
                .wrapping_add(v0)
                ^ (sum.wrapping_add(k[((sum >> 11) & 3) as usize])),
        );
    }
    v[0] = v0;
    v[1] = v1;
}

fn tea_decrypt_block(v: &mut [u32; 2], k: &[u32; 4]) {
    let (mut v0, mut v1) = (v[0], v[1]);
    let mut sum = DELTA.wrapping_mul(ROUNDS as u32);
    for _ in 0..ROUNDS {
        v1 = v1.wrapping_sub(
            ((v0 << 4) ^ (v0 >> 5))
                .wrapping_add(v0)
                ^ (sum.wrapping_add(k[((sum >> 11) & 3) as usize])),
        );
        v0 = v0.wrapping_sub(
            ((v1 << 4) ^ (v1 >> 5))
                .wrapping_add(v1)
                ^ (sum.wrapping_add(k[(sum & 3) as usize])),
        );
        sum = sum.wrapping_sub(DELTA);
    }
    v[0] = v0;
    v[1] = v1;
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

    // Derive 128-bit key by repeating/truncating password bytes
    let mut kbuf = [0u8; 16];
    for i in 0..16 {
        kbuf[i] = key_bytes[i % key_bytes.len()];
    }
    let mut key = [0u32; 4];
    for i in 0..4 {
        key[i] = u32::from_be_bytes([
            kbuf[4*i],
            kbuf[4*i + 1],
            kbuf[4*i + 2],
            kbuf[4*i + 3],
        ]);
    }

    // Read input file
    let mut file = File::open(input_path).unwrap_or_else(|e| {
        eprintln!("Failed to open {}: {}", input_path, e);
        process::exit(1);
    });
    let mut data = Vec::new();
    file.read_to_end(&mut data).unwrap();

    // Pad to multiple of 8 bytes with zeros
    let pad = (8 - (data.len() % 8)) % 8;
    data.extend(std::iter::repeat(0).take(pad));

    // Process each 8-byte block
    for chunk in data.chunks_mut(8) {
        let mut block = [
            u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]),
            u32::from_be_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]),
        ];
        if mode == "encrypt" {
            tea_encrypt_block(&mut block, &key);
        } else {
            tea_decrypt_block(&mut block, &key);
        }
        let out0 = block[0].to_be_bytes();
        let out1 = block[1].to_be_bytes();
        chunk[0..4].copy_from_slice(&out0);
        chunk[4..8].copy_from_slice(&out1);
    }

    // Write output file
    let mut out = File::create(output_path).unwrap_or_else(|e| {
        eprintln!("Failed to create {}: {}", output_path, e);
        process::exit(1);
    });
    out.write_all(&data).unwrap();

    println!("{}ed {} → {}", mode, input_path, output_path);
}
