use std::{
    fs::{File, remove_file, rename},
    io::{Read, Write},
    path::Path,
};

use clap::{Parser, Subcommand};
use rand::random;
use threefish::Threefish512;
use zeroize::Zeroize;
use anyhow::{anyhow, Result};

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

const MAGIC: &[u8; 4] = b"T5FS"; // Changed tag for 512-bit version
const VERSION: u8 = 1;
const HEADER_LEN: usize = 4 + 1 + 8;
const MAC_LEN: usize = 32;
const BLOCK_SIZE: usize = 64; // 512 bits

/// CLI for Threefish-512
#[derive(Parser)]
#[command(author, version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt file in-place
    Encrypt { path: String },
    /// Decrypt file in-place
    Decrypt { path: String },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Encrypt { path } => process(&path, true),
        Commands::Decrypt { path } => process(&path, false),
    }
}

/// Load Threefish512 key (64 bytes) + HMAC key (32 bytes)
fn load_keys() -> Result<([u8; 64], [u8; 32])> {
    let path = Path::new("key.key");
    if !path.exists() {
        return Err(anyhow!("No key.key found. Generate a key externally and place it in key.key"));
    }

    let meta = path.metadata()?;
    if meta.len() != 96 {
        return Err(anyhow!(
            "Invalid key length: expected 96 bytes (64 + 32), got {} bytes",
            meta.len()
        ));
    }

    let mut file = File::open(path)?;
    let mut full_key = [0u8; 96];
    file.read_exact(&mut full_key)?;

    let mut key = [0u8; 64];
    let mut hmac_key = [0u8; 32];
    key.copy_from_slice(&full_key[..64]);
    hmac_key.copy_from_slice(&full_key[64..]);

    Ok((key, hmac_key))
}

fn process(path_str: &str, encrypt: bool) -> Result<()> {
    let (mut key, hmac_key) = load_keys()?;
    let in_path = Path::new(path_str);
    let tmp_path = in_path.with_extension("tmp");

    if encrypt {
        // ---------- ENCRYPTION ----------
        let mut infile = File::open(in_path)?;
        let mut outfile = File::create(&tmp_path)?;
        let mut hmac = HmacSha256::new_from_slice(&hmac_key)?;

        // Write header
        outfile.write_all(MAGIC)?;
        outfile.write_all(&[VERSION])?;
        let nonce: u64 = random();
        outfile.write_all(&nonce.to_le_bytes())?;

        // Update HMAC
        hmac.update(MAGIC);
        hmac.update(&[VERSION]);
        hmac.update(&nonce.to_le_bytes());

        let mut buffer = [0u8; BLOCK_SIZE];
        let mut block_index = 0u64;

        loop {
            let n = infile.read(&mut buffer)?;
            if n == 0 {
                break;
            }

            let keystream = generate_keystream_block(&key, nonce, block_index);
            for i in 0..n {
                buffer[i] ^= keystream[i];
            }

            hmac.update(&buffer[..n]);
            outfile.write_all(&buffer[..n])?;
            block_index += 1;
        }

        let mac = hmac.finalize().into_bytes();
        outfile.write_all(&mac)?;
    } else {
        // ---------- DECRYPTION ----------
        let mut infile = File::open(in_path)?;
        let file_len = infile.metadata()?.len();

        if file_len < (HEADER_LEN + MAC_LEN) as u64 {
            return Err(anyhow!("File too short"));
        }

        let mut header = [0u8; HEADER_LEN];
        infile.read_exact(&mut header)?;
        if &header[0..4] != MAGIC {
            return Err(anyhow!("Invalid file format"));
        }
        if header[4] != VERSION {
            return Err(anyhow!("Unsupported file version"));
        }

        let mut nonce_bytes = [0u8; 8];
        nonce_bytes.copy_from_slice(&header[5..]);
        let nonce = u64::from_le_bytes(nonce_bytes);

        let ciphertext_len = file_len - HEADER_LEN as u64 - MAC_LEN as u64;
        let mut ciphertext = vec![0u8; ciphertext_len as usize];
        infile.read_exact(&mut ciphertext)?;

        let mut mac = [0u8; MAC_LEN];
        infile.read_exact(&mut mac)?;

        let mut hmac = HmacSha256::new_from_slice(&hmac_key)?;
        hmac.update(&header);
        hmac.update(&ciphertext);
        hmac.verify_slice(&mac).map_err(|_| anyhow!("Authentication failed"))?;

        let mut outfile = File::create(&tmp_path)?;
        let mut block_index = 0u64;
        let mut cursor = &ciphertext[..];

        while !cursor.is_empty() {
            let take = std::cmp::min(BLOCK_SIZE, cursor.len());
            let mut block = [0u8; BLOCK_SIZE];
            block[..take].copy_from_slice(&cursor[..take]);

            let keystream = generate_keystream_block(&key, nonce, block_index);
            for i in 0..take {
                block[i] ^= keystream[i];
            }

            outfile.write_all(&block[..take])?;
            cursor = &cursor[take..];
            block_index += 1;
        }
    }

    key.zeroize();
    remove_file(in_path).ok();
    rename(tmp_path, in_path)?;
    Ok(())
}

/// Generate 64-byte keystream block using Threefish512 safely
fn generate_keystream_block(key: &[u8; 64], nonce: u64, block_index: u64) -> [u8; 64] {
    let mut key_u64 = [0u64; 8];
    for (i, chunk) in key.chunks_exact(8).enumerate() {
        key_u64[i] = u64::from_le_bytes(chunk.try_into().unwrap());
    }

    let tweak = [nonce, block_index];
    let mut block = [0u64; 8];
    block[0] = block_index;

    let cipher = Threefish512::new_with_tweak_u64(&key_u64, &tweak);
    cipher.encrypt_block_u64(&mut block);

    let mut out = [0u8; 64];
    for (i, val) in block.iter().enumerate() {
        out[i * 8..(i + 1) * 8].copy_from_slice(&val.to_le_bytes());
    }

    out
}
