use aes::Aes256;
use block_modes::{BlockMode, Ofb, block_padding::NoPadding};
use rand::{rngs::OsRng, RngCore};
use std::{env, fs, process::exit};
use anyhow::{Result, Context};

type Aes256Ofb = Ofb<Aes256, NoPadding>;

const IV_LEN: usize = 16;
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

            let mut iv = [0u8; IV_LEN];
            OsRng.fill_bytes(&mut iv);

            let cipher = Aes256Ofb::new_from_slices(&key_bytes, &iv)
                .map_err(|e| anyhow::anyhow!("Encryption error: {:?}", e))?;

            let ciphertext = cipher.encrypt_vec(&plaintext);

            let mut output_data = iv.to_vec();
            output_data.extend_from_slice(&ciphertext);

            fs::write(output_file, &output_data)
                .context("Failed to write output file")?;

            println!("✅ Encrypted → {}", output_file);
        }
        "decrypt" => {
            let input_data = fs::read(input_file)
                .context("Failed to read input file")?;

            if input_data.len() < IV_LEN {
                anyhow::bail!("Input file too short to contain IV");
            }

            let (iv, ciphertext) = input_data.split_at(IV_LEN);

            let cipher = Aes256Ofb::new_from_slices(&key_bytes, iv)
                .map_err(|e| anyhow::anyhow!("Decryption error: {:?}", e))?;

            let plaintext = cipher.decrypt_vec(ciphertext)
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
