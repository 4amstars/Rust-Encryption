mod cli;
mod modes;
mod utils;
mod entropy;

use clap::Parser;
use cli::{Cli, Mode};

fn main() {
    let cli = Cli::parse();

    // ENTROPY TEST MODE
    if cli.mode == Mode::EntropyTest {
        let input_file = cli.input.as_ref().expect("Please provide --input <file> for entropy analysis.");
        match entropy::analyze_entropy(input_file, "report.html") {
            Ok(_) => println!("✅ Entropy report saved to report.html"),
            Err(err) => eprintln!("❌ Error: {}", err),
        }
        return;
    }

    // KEY GENERATION MODES (requires size)
    let size_str = match &cli.size {
        Some(s) => s,
        None => {
            eprintln!("❌ Error: You must provide a SIZE for key generation modes.");
            eprintln!("👉 Example: cargo run -- 1mb -p password --mode argon2");
            std::process::exit(1);
        }
    };

    let key_size = utils::parse_size(size_str).expect("Invalid size format.");
    let count = cli.count.unwrap_or(1);

    let filenames = match cli.mode {
        Mode::Argon2 => modes::generate_argon2(&cli, key_size, count),
        Mode::Scrypt => modes::generate_scrypt(&cli, key_size, count),
        Mode::Pbkdf2 => modes::generate_pbkdf2(&cli, key_size, count),
        Mode::DualPass => modes::generate_dualpass(&cli, key_size, count),
        Mode::XorPrng => modes::generate_xor_prng(&cli, key_size, count),
        Mode::Random => modes::generate_random(&cli, key_size, count),
        Mode::MultiKey => modes::generate_multikey(&cli, key_size, count),
        Mode::EntropyTest => unreachable!(), // Already handled above
    };

    // Optional: Rename output file
    if let Some(custom_name) = &cli.output {
        if filenames.len() == 1 {
            let original = &filenames[0];
            if std::path::Path::new(custom_name).exists() {
                eprintln!("❌ File '{}' already exists. Aborting rename.", custom_name);
            } else {
                match std::fs::rename(original, custom_name) {
                    Ok(_) => println!("🔄 Renamed '{}' → '{}'", original, custom_name),
                    Err(e) => eprintln!("⚠️ Failed to rename file: {}", e),
                }
            }
        } else {
            println!("⚠️ Warning: --output is ignored when generating multiple keys (--count > 1).");
        }
    }

    // Optional: Print checksums
    if cli.checksum {
        for filename in filenames {
            match entropy::sha256_checksum(&filename) {
                Ok(hash) => println!("{}: SHA-256 = {}", filename, hash),
                Err(err) => eprintln!("❌ Error generating checksum for {}: {}", filename, err),
            }
        }
    }
}
