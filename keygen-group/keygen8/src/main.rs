use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::env;
use std::time::Instant;

use argon2::{Argon2, Params, Algorithm, Version, PasswordHasher};
use blake3;
use password_hash::SaltString;
use rpassword::prompt_password;

// 🔐 Argon2id KDF Configuration
//
// These values control how expensive it is to derive a key from a password.
// Higher values = more security, but slower and higher resource usage.
//
// 💡 This only affects how the initial 32-byte seed is derived.
//     The actual key stream (BLAKE3) is extremely fast and cryptographically secure.

// 🧠 ARGON2_MEMORY_KIB:
// - Units: kibibytes (1 MiB = 1024 KiB)
// - Default recommendation: 512 MiB (524_288 KiB)
// - Max safe value: ~2–4 GiB (2_097_152 to 4_194_304 KiB)
// - Must not exceed physical RAM or system may crash
const ARGON2_MEMORY_KIB: u32 = 1024 * 512; // 512 MiB

// 🧠 ARGON2_TIME_COST:
// - Number of passes over memory
// - Default: 3
// - Hardened: 10–20
// - Max safe value: 100+ (very slow!)
const ARGON2_TIME_COST: u32 = 10;

// 🧠 ARGON2_PARALLELISM:
// - Number of threads used during hash
// - Recommended: 1 for deterministic CLI tools
// - Max: Number of logical CPU cores (but higher = more CPU usage)
// - Warning: using >1 can make performance vary across systems
const ARGON2_PARALLELISM: u32 = 1;

// 🔁 Compile-Time Salt
// - Changing this changes the entire key universe
// - Leave fixed for consistent output, or change to reset determinism
// - Must be static and hardcoded for reproducibility
const COMPILE_TIME_SALT: &[u8] = b"change-this-salt-to-change-key-universe";

// 🧾 Log to both stderr and error.txt
fn log_error(msg: &str) {
    eprintln!("{}", msg);
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open("error.txt") {
        let _ = writeln!(file, "{}", msg);
    }
}

// 🔑 Derive a secure 32-byte seed from password using Argon2id
fn derive_seed(password: &str) -> [u8; 32] {
    let salt = SaltString::encode_b64(COMPILE_TIME_SALT).unwrap();

    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_TIME_COST,
        ARGON2_PARALLELISM,
        None,
    ).unwrap();

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let hash = match argon2.hash_password(password.as_bytes(), &salt) {
        Ok(h) => h,
        Err(e) => {
            log_error(&format!("❌ Argon2id hashing failed: {}", e));
            std::process::exit(1);
        }
    };

    let raw = hash.hash.unwrap();
    let hash_bytes = raw.as_bytes();

    let mut seed = [0u8; 32];
    seed.copy_from_slice(&hash_bytes[..32]);
    seed
}

// 🧵 Stream BLAKE3 output into key file using a buffer
fn write_key_file(output: &str, seed: [u8; 32], size: usize) -> io::Result<()> {
    let mut xof = blake3::Hasher::new_keyed(&seed).finalize_xof();
    let mut buffer = [0u8; 8192];

    let file = File::create(output)?;
    let mut writer = BufWriter::new(file);

    let mut remaining = size;
    while remaining > 0 {
        let chunk = remaining.min(buffer.len());
        xof.fill(&mut buffer[..chunk]);
        writer.write_all(&buffer[..chunk])?;
        remaining -= chunk;
    }

    writer.flush()?;
    Ok(())
}

// 🔢 Parse human-friendly sizes like "10mb", "5gb", etc.
fn parse_size(arg: &str) -> Option<usize> {
    let arg = arg.trim().to_lowercase();
    let (num, mult) = if let Some(stripped) = arg.strip_suffix("gb") {
        (stripped, 1024 * 1024 * 1024)
    } else if let Some(stripped) = arg.strip_suffix("mb") {
        (stripped, 1024 * 1024)
    } else if let Some(stripped) = arg.strip_suffix("kb") {
        (stripped, 1024)
    } else {
        (arg.as_str(), 1)
    };

    num.parse::<f64>()
        .ok()
        .map(|n| (n * mult as f64).round() as usize)
}

// 🚀 Entry point: parse args, derive seed, write key, log results
fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        log_error("Usage: dkey <size_in_bytes|1kb|5mb|50gb>");
        std::process::exit(1);
    }

    let size = match parse_size(&args[1]) {
        Some(s) => s,
        None => {
            log_error(&format!("❌ Invalid size: '{}'", args[1]));
            std::process::exit(1);
        }
    };

    let password1 = prompt_password("🔐 Enter password: ").unwrap_or_else(|e| {
        log_error(&format!("❌ Failed to read password: {}", e));
        std::process::exit(1);
    });

    let password2 = prompt_password("🔐 Confirm password: ").unwrap_or_else(|e| {
        log_error(&format!("❌ Failed to read confirmation: {}", e));
        std::process::exit(1);
    });

    if password1 != password2 {
        log_error("❌ Passwords do not match. Aborting.");
        std::process::exit(1);
    }

    let output = "key.key";
    println!("📦 Generating deterministic key of {} bytes to '{}'", size, output);

    let start = Instant::now();
    let seed = derive_seed(&password1);

    if let Err(e) = write_key_file(output, seed, size) {
        log_error(&format!("❌ Failed to write key: {}", e));
        std::process::exit(1);
    }

    println!("✅ Key generated successfully in {:.2?}", start.elapsed());
    Ok(())
}
