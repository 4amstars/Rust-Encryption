// Cargo.toml dependencies:
//
// [dependencies]
// argon2 = "0.5.3"
// rand_chacha = "0.9.0"
// rand_core = "0.9.0"

use std::env;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::process::exit;

use argon2::{Argon2, Params, Version, Algorithm};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

/// A collection of configuration options for generating a deterministic key.
///
/// Adjust these at compile time to change the derived keys, Argon2 parameters, etc.
/// If you change anything here, previously generated keys will no longer match.
struct Config {
    //
    // Key Generation Options
    //
    /// The maximum allowed key size in bytes (e.g., 5 GB).
    max_size_bytes: u64,
    /// The size in bytes of the buffer used for chunked writing.
    chunk_size_bytes: usize,
    /// The maximum allowed password length (in bytes).
    max_password_length: usize,

    //
    // Argon2 Parameter Options
    //
    /// Argon2 memory cost in KiB.
    argon2_memory_kib: u32,
    /// Argon2 iteration count.
    argon2_iterations: u32,
    /// Argon2 parallelism (number of lanes).
    argon2_parallelism: u32,

    //
    // Acceptable Ranges for Argon2 parameters
    //
    min_argon2_memory_kib: u32,
    max_argon2_memory_kib: u32,
    min_argon2_iterations: u32,
    max_argon2_iterations: u32,
    min_argon2_parallelism: u32,
    max_argon2_parallelism: u32,

    //
    // KDF Salt
    //
    /// A fixed salt, making key derivation fully deterministic.
    /// Changing this string will result in a completely different key for the same password.
    kdf_salt: &'static str,

    //
    // Derived Seed Size
    //
    /// The number of bytes derived from Argon2 that will seed our PRNG.
    derived_seed_size: usize,

    //
    // Output Filename
    //
    /// The file to which the generated key is written.
    output_filename: &'static str,
}

impl Config {
    /// Create a default configuration suitable for many use-cases.
    /// Adjust as desired before compiling.
    fn default() -> Self {
        Self {
            //
            // Key Generation Options
            //
            max_size_bytes: 5 * 1024 * 1024 * 1024, // 5 GB
            chunk_size_bytes: 64 * 1024,            // 64 KiB
            max_password_length: 1024,              // 1 KB

            //
            // Argon2 Parameter Options
            //
            argon2_memory_kib: 65536, // 64 MiB
            argon2_iterations: 3,
            argon2_parallelism: 1,

            //
            // Acceptable Ranges
            //
            min_argon2_memory_kib: 8192,      // 8 MiB
            max_argon2_memory_kib: 1048576,   // 1 GiB
            min_argon2_iterations: 1,
            max_argon2_iterations: 10,
            min_argon2_parallelism: 1,
            max_argon2_parallelism: 8,

            //
            // KDF Salt
            //
            kdf_salt: "BetterDeterministicKeySalt_v2",

            //
            // Seed Size
            //
            derived_seed_size: 32,

            //
            // Output File
            //
            output_filename: "key.key",
        }
    }
}

/// Validates command-line inputs and configuration.
fn validate_args(args: &[String], config: &Config) -> Result<(u64, String), String> {
    if args.len() != 3 {
        return Err(format!("Usage: {} <size_in_bytes> <password>", args[0]));
    }

    // Parse key size
    let size: u64 = args[1].parse().map_err(|_| format!("Invalid size: '{}'", args[1]))?;
    if size < 1 || size > config.max_size_bytes {
        return Err(format!(
            "Error: size must be between 1 byte and {} bytes (inclusive).",
            config.max_size_bytes
        ));
    }

    let password = &args[2];
    if password.is_empty() {
        return Err("Error: Password cannot be empty.".to_string());
    }

    if password.len() > config.max_password_length {
        return Err(format!(
            "Error: Password is too long (max {} characters allowed).",
            config.max_password_length
        ));
    }

    Ok((size, password.to_owned()))
}

/// Validates the Argon2 parameters are within acceptable ranges.
fn validate_argon2_params(config: &Config) -> Result<(), String> {
    if config.argon2_memory_kib < config.min_argon2_memory_kib
        || config.argon2_memory_kib > config.max_argon2_memory_kib
    {
        return Err(format!(
            "Error: Argon2 memory cost must be between {} and {} KiB.",
            config.min_argon2_memory_kib, config.max_argon2_memory_kib
        ));
    }

    if config.argon2_iterations < config.min_argon2_iterations
        || config.argon2_iterations > config.max_argon2_iterations
    {
        return Err(format!(
            "Error: Argon2 iteration count must be between {} and {}.",
            config.min_argon2_iterations, config.max_argon2_iterations
        ));
    }

    if config.argon2_parallelism < config.min_argon2_parallelism
        || config.argon2_parallelism > config.max_argon2_parallelism
    {
        return Err(format!(
            "Error: Argon2 parallelism (lanes) must be between {} and {}.",
            config.min_argon2_parallelism, config.max_argon2_parallelism
        ));
    }

    Ok(())
}

/// Creates an `Argon2` instance with the given configuration.
fn build_argon2(config: &Config) -> Result<Argon2<'static>, String> {
    let params = Params::new(
        config.argon2_memory_kib,
        config.argon2_iterations,
        config.argon2_parallelism,
        None,
    )
    .map_err(|e| format!("Error setting Argon2 parameters: {}", e))?;

    // Use Argon2id (recommended in most scenarios).
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    Ok(argon2)
}

/// Derives a seed from the given password using Argon2.
/// Returns a vector (or array) of bytes that can be used to seed a PRNG.
fn derive_seed(argon2: &Argon2, config: &Config, password: &str) -> Result<Vec<u8>, String> {
    let mut seed = vec![0u8; config.derived_seed_size];
    argon2
        .hash_password_into(password.as_bytes(), config.kdf_salt.as_bytes(), &mut seed)
        .map_err(|e| format!("Error deriving seed: {}", e))?;

    Ok(seed)
}

/// Generates the key bytes (of size `key_size`) deterministically and writes them to the specified output file.
fn generate_key(seed: &[u8], config: &Config, key_size: u64) -> Result<(), String> {
    // Initialize ChaCha20 PRNG with the derived seed.
    let mut rng = ChaCha20Rng::from_seed(seed.try_into().expect("Seed size mismatch"));

    // Create output file with buffering.
    let file = File::create(config.output_filename)
        .map_err(|e| format!("Failed to create file '{}': {}", config.output_filename, e))?;
    let mut writer = BufWriter::new(file);

    // Write the key in chunks to avoid large memory usage.
    let mut remaining = key_size;
    let mut buffer = vec![0u8; config.chunk_size_bytes];

    while remaining > 0 {
        let chunk_size = if remaining as usize > config.chunk_size_bytes {
            config.chunk_size_bytes
        } else {
            remaining as usize
        };

        rng.fill_bytes(&mut buffer[..chunk_size]);
        writer
            .write_all(&buffer[..chunk_size])
            .map_err(|e| format!("Error writing to file: {}", e))?;

        remaining -= chunk_size as u64;
    }

    writer.flush().map_err(|e| format!("Error flushing file: {}", e))?;
    Ok(())
}

fn main() {
    // Feel free to build a custom config if you want to override the defaults.
    // For example:
    // let config = Config {
    //     argon2_iterations: 5,
    //     ..Config::default()
    // };
    let config = Config::default();

    // Read and validate command-line arguments.
    let args: Vec<String> = env::args().collect();
    let (size_in_bytes, password) = match validate_args(&args, &config) {
        Ok(values) => values,
        Err(e) => {
            eprintln!("{}", e);
            exit(1);
        }
    };

    // Validate Argon2 parameters in the config.
    if let Err(e) = validate_argon2_params(&config) {
        eprintln!("{}", e);
        exit(1);
    }

    // Build the Argon2 instance.
    let argon2 = match build_argon2(&config) {
        Ok(a2) => a2,
        Err(e) => {
            eprintln!("{}", e);
            exit(1);
        }
    };

    // Derive the seed from the password.
    let seed = match derive_seed(&argon2, &config, &password) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{}", e);
            exit(1);
        }
    };

    // Generate and write out the deterministic key.
    if let Err(e) = generate_key(&seed, &config, size_in_bytes) {
        eprintln!("{}", e);
        exit(1);
    }

    println!(
        "Deterministic key of {} bytes generated and saved to '{}'.",
        size_in_bytes, config.output_filename
    );
}

