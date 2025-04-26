use aes::Aes256;
use xts_mode::Xts128 as Aes256Xts;
use aes::cipher::{KeyInit, generic_array::GenericArray};
use std::{env, fs, process::exit};
use anyhow::{Result, Context};

const KEY_FILE: &str = "key.key";
const KEY_LEN: usize = 64;
const TWEAK_U128: u128 = 0;

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
    if key_bytes.len() != KEY_LEN {
        anyhow::bail!("Key must be 64 bytes (2 x 256-bit keys for AES-XTS)");
    }

    let key1 = GenericArray::from_slice(&key_bytes[..32]);
    let key2 = GenericArray::from_slice(&key_bytes[32..]);

    let cipher = Aes256Xts::new(
        Aes256::new(key1),
        Aes256::new(key2),
    );

    let mut data = fs::read(input_file)
        .context("Failed to read input file")?;

    let tweak = TWEAK_U128.to_le_bytes(); // ✅ convert to [u8; 16]

    match mode {
        "encrypt" => {
            cipher.encrypt_sector(&mut data, tweak);
            fs::write(output_file, &data)
                .context("Failed to write encrypted output")?;
            println!("✅ Encrypted → {}", output_file);
        }
        "decrypt" => {
            cipher.decrypt_sector(&mut data, tweak);
            fs::write(output_file, &data)
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
