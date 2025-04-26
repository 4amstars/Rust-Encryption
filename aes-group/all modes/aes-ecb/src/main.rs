use aes::Aes256;
use block_modes::{BlockMode, Ecb, block_padding::Pkcs7};
use std::{env, fs, process::exit};
use anyhow::{Result, Context};

type Aes256Ecb = Ecb<Aes256, Pkcs7>;

const KEY_FILE: &str = "key.key";

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() != 4 {
        eprintln!("Usage: {} <encrypt|decrypt> <input_file> <output_file>", args[0]);
        exit(1);
    }

    let mode = args[1].as_str();
    let input_file = &args[2];
    let output_file = &args[3];

    let key_bytes = fs::read(KEY_FILE)
        .context("Failed to read key.key file")?;
    if key_bytes.len() != 32 {
        anyhow::bail!("Key file must be exactly 32 bytes (256-bit)");
    }

    match mode {
        "encrypt" => {
            let plaintext = fs::read(input_file)
                .context("Failed to read input file")?;

            let cipher = Aes256Ecb::new_from_slices(&key_bytes, &[])
                .map_err(|e| anyhow::anyhow!("Encryption error: {:?}", e))?;

            let ciphertext = cipher.encrypt_vec(&plaintext);

            fs::write(output_file, &ciphertext)
                .context("Failed to write output file")?;

            println!("✅ Encrypted → {}", output_file);
        }
        "decrypt" => {
            let ciphertext = fs::read(input_file)
                .context("Failed to read input file")?;

            let cipher = Aes256Ecb::new_from_slices(&key_bytes, &[])
                .map_err(|e| anyhow::anyhow!("Decryption error: {:?}", e))?;

            let plaintext = cipher.decrypt_vec(&ciphertext)
                .map_err(|e| anyhow::anyhow!("Decryption failed: {:?}", e))?;

            fs::write(output_file, &plaintext)
                .context("Failed to write decrypted output")?;

            println!("✅ Decrypted → {}", output_file);
        }
        _ => {
            eprintln!("Invalid mode '{}'. Use 'encrypt' or 'decrypt'.", mode);
            exit(1);
        }
    }

    Ok(())
}
