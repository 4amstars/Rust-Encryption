use std::{
    fs::File,
    io::{self, BufWriter, Write},
    process,
    time::Instant,
};

use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use blake3;
use clap::Parser;
use password_hash::{PasswordHasher, SaltString};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rpassword::prompt_password;
use zeroize::Zeroize;

const ARGON2_MEMORY_KIB: u32 = 512 * 1024; // 512 MiB
const ARGON2_TIME_COST: u32 = 10;
const ARGON2_PARALLELISM: u32 = 1;
const COMPILE_TIME_SALT: &[u8] = b"change-this-salt-to-change-key-universe";

#[derive(Parser)]
#[command(author, version, about = "Generate deterministic cryptographic keys")]
struct Args {
    /// Key size (e.g. 10kb, 5mb, 1gb)
    size: String,
    /// Output file path
    #[arg(short, long, default_value = "key.key")]
    output: String,
    /// Compile-time salt override (raw base64)
    #[arg(short, long)]
    salt: Option<String>,
    /// Algorithm: "blake3" or "chacha"
    #[arg(short, long, default_value = "blake3")]
    algo: String,
    /// Argon2 memory in KiB
    #[arg(long, default_value_t = ARGON2_MEMORY_KIB)]
    argon2_memory: u32,
    /// Argon2 time cost
    #[arg(long, default_value_t = ARGON2_TIME_COST)]
    argon2_time: u32,
    /// Argon2 parallelism
    #[arg(long, default_value_t = ARGON2_PARALLELISM)]
    argon2_par: u32,
}

fn derive_seed(
    password: &str,
    salt_bytes: &[u8],
    mem: u32,
    time: u32,
    par: u32,
) -> [u8; 32] {
    let salt = SaltString::encode_b64(salt_bytes).expect("Invalid salt");
    let params = Params::new(mem, time, par, None).expect("Invalid Argon2 params");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .unwrap_or_else(|e| {
            eprintln!("Argon2 hashing failed: {}", e);
            process::exit(1);
        });
    let raw = hash.hash.unwrap();
    let bytes = raw.as_bytes();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes[..32]);
    seed
}

fn write_blake3(output: &str, seed: &[u8; 32], size: usize) -> io::Result<()> {
    let mut xof = blake3::Hasher::new_keyed(seed).finalize_xof();
    let mut buffer = [0u8; 8192];
    let mut writer = BufWriter::new(File::create(output)?);
    let mut remaining = size;
    while remaining > 0 {
        let chunk = remaining.min(buffer.len());
        xof.fill(&mut buffer[..chunk]);
        writer.write_all(&buffer[..chunk])?;
        remaining -= chunk;
    }
    writer.flush()
}

fn write_chacha(output: &str, seed: &[u8; 32], size: usize) -> io::Result<()> {
    let mut rng = ChaCha20Rng::from_seed(*seed);
    let mut buffer = [0u8; 8192];
    let mut writer = BufWriter::new(File::create(output)?);
    let mut remaining = size;
    while remaining > 0 {
        rng.fill_bytes(&mut buffer);
        let chunk = remaining.min(buffer.len());
        writer.write_all(&buffer[..chunk])?;
        remaining -= chunk;
    }
    writer.flush()
}

fn parse_size(arg: &str) -> Option<usize> {
    let s = arg.trim().to_lowercase();
    let (num, mul) = if let Some(n) = s.strip_suffix("gb") {
        (n, 1024 * 1024 * 1024)
    } else if let Some(n) = s.strip_suffix("mb") {
        (n, 1024 * 1024)
    } else if let Some(n) = s.strip_suffix("kb") {
        (n, 1024)
    } else {
        (s.as_str(), 1)
    };

    num.parse::<f64>()
        .ok()
        .map(|v| (v * mul as f64).round() as usize)
}

fn main() -> io::Result<()> {
    let args = Args::parse();
    let size = parse_size(&args.size).unwrap_or_else(|| {
        eprintln!("Invalid size: {}", args.size);
        process::exit(1);
    });

    let mut pwd1 = prompt_password("🔐 Enter password: ").unwrap_or_else(|e| {
        eprintln!("Failed to read password: {}", e);
        process::exit(1);
    });
    let mut pwd2 = prompt_password("🔐 Confirm password: ").unwrap_or_else(|e| {
        eprintln!("Failed to read confirmation: {}", e);
        process::exit(1);
    });
    if pwd1 != pwd2 {
        eprintln!("❌ Passwords do not match. Aborting.");
        process::exit(1);
    }

    let salt_bytes = args
        .salt
        .as_deref()
        .map(|s| STANDARD.decode(s).unwrap_or_else(|_| {
            eprintln!("Invalid base64 salt override");
            process::exit(1);
        }))
        .unwrap_or_else(|| COMPILE_TIME_SALT.to_vec());

    println!("📦 Generating {} bytes to '{}'", size, args.output);
    let start = Instant::now();
    let mut seed = derive_seed(
        &pwd1,
        &salt_bytes,
        args.argon2_memory,
        args.argon2_time,
        args.argon2_par,
    );
    pwd1.zeroize();
    pwd2.zeroize();

    let result = match args.algo.as_str() {
        "chacha" => write_chacha(&args.output, &seed, size),
        _ => write_blake3(&args.output, &seed, size),
    };

    seed.zeroize();
    result.expect("Failed to write key file");
    println!("✅ Key generated in {:.2?}", start.elapsed());
    Ok(())
}

