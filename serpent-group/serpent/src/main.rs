use anyhow::{Context, Result};
use hmac::{Hmac, Mac};
use rand::RngCore;
use serpent::cipher::{Block, BlockDecrypt, BlockEncrypt, KeyInit as SerpentKeyInit};
use serpent::Serpent;
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::path::Path;

// Type alias for HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;

const BLOCK_SIZE: usize = 16;
const TAG_SIZE: usize = 32;

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 || !(args[1] == "E" || args[1] == "D") {
        eprintln!("Usage: {} [E|D] <filename>", args[0]);
        std::process::exit(1);
    }

    let encrypt = args[1] == "E";
    let path = Path::new(&args[2]);

    let key_bytes = fs::read("key.key").context("Failed to read key.key")?;
    if key_bytes.len() != 32 {
        anyhow::bail!("key.key must be exactly 32 bytes");
    }

    // Derive HMAC key from encryption key (via SHA-256)
    let mut hasher = Sha256::new();
    hasher.update(&key_bytes);
    let hmac_key = hasher.finalize().to_vec();

    let data = fs::read(path).with_context(|| format!("Reading file: {:?}", path))?;
    let result = if encrypt {
        encrypt_file(&data, &key_bytes, &hmac_key)?
    } else {
        decrypt_file(&data, &key_bytes, &hmac_key)?
    };

    let tmp_path = path.with_extension("tmp");
    fs::write(&tmp_path, &result).context("Writing temp file")?;
    fs::rename(&tmp_path, path).context("Replacing original file")?;

    println!("{}ion successful: {:?}", if encrypt { "Encrypt" } else { "Decrypt" }, path);
    Ok(())
}

fn encrypt_file(data: &[u8], key: &[u8], hmac_key: &[u8]) -> Result<Vec<u8>> {
    let mut iv = [0u8; BLOCK_SIZE];
    rand::thread_rng().fill_bytes(&mut iv);

    // PKCS#7 padding
    let mut pt = data.to_vec();
    let pad_len = BLOCK_SIZE - (pt.len() % BLOCK_SIZE);
    pt.extend(std::iter::repeat(pad_len as u8).take(pad_len));

    let cipher = Serpent::new_from_slice(key)?;
    let mut ct = Vec::with_capacity(pt.len());
    let mut prev_block = iv;

    for chunk in pt.chunks(BLOCK_SIZE) {
        let mut block = [0u8; BLOCK_SIZE];
        for i in 0..BLOCK_SIZE {
            block[i] = chunk[i] ^ prev_block[i];
        }
        let mut block_enc = Block::<Serpent>::clone_from_slice(&block);
        cipher.encrypt_block(&mut block_enc);
        let encrypted = block_enc.to_vec();
        prev_block.copy_from_slice(&encrypted);
        ct.extend_from_slice(&encrypted);
    }

    let mut mac = <HmacSha256 as hmac::digest::KeyInit>::new_from_slice(hmac_key)
        .context("HMAC init failed")?;
    mac.update(&iv);
    mac.update(&ct);
    let tag = mac.finalize().into_bytes();

    let mut out = Vec::with_capacity(iv.len() + ct.len() + tag.len());
    out.extend_from_slice(&iv);
    out.extend_from_slice(&ct);
    out.extend_from_slice(&tag);
    Ok(out)
}

fn decrypt_file(data: &[u8], key: &[u8], hmac_key: &[u8]) -> Result<Vec<u8>> {
    if data.len() < BLOCK_SIZE + TAG_SIZE {
        anyhow::bail!("Data too short to decrypt");
    }

    let iv = &data[..BLOCK_SIZE];
    let tag = &data[data.len() - TAG_SIZE..];
    let ct = &data[BLOCK_SIZE..data.len() - TAG_SIZE];

    let mut mac = <HmacSha256 as hmac::digest::KeyInit>::new_from_slice(hmac_key)
        .context("HMAC init failed")?;
    mac.update(iv);
    mac.update(ct);
    mac.verify(tag.into()).context("HMAC verification failed")?;

    let cipher = Serpent::new_from_slice(key)?;
    let mut pt = Vec::with_capacity(ct.len());
    let mut prev_block = <[u8; BLOCK_SIZE]>::try_from(iv).unwrap();

    for chunk in ct.chunks(BLOCK_SIZE) {
        let mut block = Block::<Serpent>::clone_from_slice(chunk);
        cipher.decrypt_block(&mut block);
        let db = block.to_vec();
        let mut plain_block = [0u8; BLOCK_SIZE];
        for i in 0..BLOCK_SIZE {
            plain_block[i] = db[i] ^ prev_block[i];
        }
        prev_block.copy_from_slice(chunk);
        pt.extend_from_slice(&plain_block);
    }

    let pad_len = *pt.last().ok_or_else(|| anyhow::anyhow!("Empty plaintext"))? as usize;
    if pad_len == 0 || pad_len > BLOCK_SIZE
        || !pt[pt.len() - pad_len..].iter().all(|&b| b as usize == pad_len)
    {
        anyhow::bail!("Invalid PKCS#7 padding");
    }

    pt.truncate(pt.len() - pad_len);
    Ok(pt)
}
