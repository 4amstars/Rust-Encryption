use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, KeyInit, OsRng, generic_array::GenericArray, rand_core::RngCore},
};
use std::{env, fs, process::exit};
use anyhow::{Result, Context};

const NONCE_LEN: usize = 12;
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

    let key = GenericArray::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    match mode {
        "encrypt" => {
            let plaintext = fs::read(input_file)
                .context("Failed to read input file")?;

            let mut nonce_bytes = [0u8; NONCE_LEN];
            OsRng.fill_bytes(&mut nonce_bytes);
            let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);

            let ciphertext = cipher.encrypt(nonce, plaintext.as_ref())
                .map_err(|e| anyhow::anyhow!("Encryption failed: {:?}", e))?;

            let mut output_data = nonce_bytes.to_vec();
            output_data.extend_from_slice(&ciphertext);

            fs::write(output_file, &output_data)
                .context("Failed to write output file")?;

            println!("✅ Encrypted → {}", output_file);
        }
        "decrypt" => {
            let input_data = fs::read(input_file)
                .context("Failed to read input file")?;

            if input_data.len() < NONCE_LEN {
                anyhow::bail!("Input file too short to contain nonce");
            }

            let (nonce_bytes, ciphertext) = input_data.split_at(NONCE_LEN);
            let nonce = aes_gcm::Nonce::from_slice(nonce_bytes);

            let plaintext = cipher.decrypt(nonce, ciphertext)
                .map_err(|e| anyhow::anyhow!("Decryption/authentication failed: {:?}", e))?;

            fs::write(output_file, &plaintext)
                .context("Failed to write decrypted output file")?;

            println!("✅ Decrypted → {}", output_file);
        }
        _ => {
            eprintln!("Invalid mode '{}'. Use 'encrypt' or 'decrypt'.", mode);
            exit(1);
        }
    }

    Ok(())
}
