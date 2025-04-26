use std::fs::File;
use std::io::{BufWriter, Write};

use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

/// Parses human-friendly size strings like "512KB", "1MB", "2GB"
pub fn parse_size(input: &str) -> Result<u64, String> {
    let lower = input.to_lowercase();
    let (num_str, multiplier): (&str, u64) = if lower.ends_with("gb") {
        (&lower[..lower.len() - 2], 1024 * 1024 * 1024)
    } else if lower.ends_with("mb") {
        (&lower[..lower.len() - 2], 1024 * 1024)
    } else if lower.ends_with("kb") {
        (&lower[..lower.len() - 2], 1024)
    } else if lower.ends_with("b") {
        (&lower[..lower.len() - 1], 1)
    } else {
        (&lower, 1)
    };

    num_str.trim()
        .parse::<u64>()
        .map(|n| n * multiplier)
        .map_err(|_| format!("Invalid size: '{}'", input))
}

/// Gets the password or throws a user-friendly error
pub fn require_password(p: &Option<String>) -> String {
    p.as_ref()
        .cloned()
        .expect("Password is required. Use -p or --password <value>")
}

/// Writes key bytes to a file
pub fn write_to_file(path: &str, data: &[u8]) -> Result<(), String> {
    let file = File::create(path).map_err(|e| e.to_string())?;
    let mut writer = BufWriter::new(file);
    writer.write_all(data).map_err(|e| e.to_string())?;
    writer.flush().map_err(|e| e.to_string())?;
    Ok(())
}

/// XORs two byte slices together
pub fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

/// Generates pseudorandom data deterministically from a ChaCha20 RNG
pub fn prng(seed: &[u8], size: usize) -> Vec<u8> {
    let mut rng = ChaCha20Rng::from_seed(seed.try_into().expect("Seed size mismatch"));
    let mut output = vec![0u8; size];
    rng.fill_bytes(&mut output);
    output
}
