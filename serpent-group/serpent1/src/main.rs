use anyhow::{Context, Result};
use hmac::{Hmac, Mac};
use rand::{RngCore, rngs::OsRng};
use serpent::cipher::{Block, BlockDecrypt, BlockEncrypt, KeyInit as SerpentKeyInit};
use serpent::Serpent;
use sha2::{Sha256, Digest};
use std::env;
use std::fs;
use std::path::Path;
use rpassword::prompt_password;
use argon2::{Argon2, PasswordHasher};
use argon2::password_hash::SaltString;

type HmacSha256 = Hmac<Sha256>;

const BLOCK_SIZE: usize = 16;
const TAG_SIZE: usize = 32;
const SALT_LEN: usize = 16;

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 || !(args[1] == "E" || args[1] == "D") {
        eprintln!("Usage: {} [E|D] <filename>", args[0]);
        std::process::exit(1);
    }

    let encrypt = args[1] == "E";
    let path = Path::new(&args[2]);

    // Prompt for password (twice if encrypting)
    let password = if encrypt {
        let pw1 = prompt_password("Enter password: ")?;
        let pw2 = prompt_password("Confirm password: ")?;
        if pw1 != pw2 {
            eprintln!("Passwords do not match.");
            std::process::exit(1);
        }
        pw1
    } else {
        prompt_password("Enter password: ")?
    };

    let data = fs::read(path).with_context(|| format!("Reading file: {:?}", path))?;
    let result = if encrypt {
        encrypt_file(&data, &password)?
    } else {
        decrypt_file(&data, &password)?
    };

    let tmp_path = path.with_extension("tmp");
    fs::write(&tmp_path, &result).context("Writing output file")?;
    fs::rename(&tmp_path, path).context("Replacing original file")?;

    println!("{}ion successful: {:?}", if encrypt { "Encrypt" } else { "Decrypt" }, path);
    Ok(())
}

fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let argon2 = Argon2::default();
    let salt_str = SaltString::encode_b64(salt)
        .map_err(|e| anyhow::anyhow!("Invalid salt: {}", e))?;

    let hash = argon2
        .hash_password(password.as_bytes(), &salt_str)
        .map_err(|e| anyhow::anyhow!("Key derivation failed: {}", e))?;

    let raw = hash.hash.ok_or_else(|| anyhow::anyhow!("Argon2 hash missing"))?;
    let mut key = [0u8; 32];
    key.copy_from_slice(&raw.as_bytes()[..32]);
    Ok(key)
}

fn encrypt_file(data: &[u8], password: &str) -> Result<Vec<u8>> {
    let mut iv = [0u8; BLOCK_SIZE];
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut iv);
    OsRng.fill_bytes(&mut salt);

    let key = derive_key(password, &salt)?;
    let mut hasher = Sha256::new();
    hasher.update(&key);
    let hmac_key = hasher.finalize();

    let mut pt = data.to_vec();
    let pad_len = BLOCK_SIZE - (pt.len() % BLOCK_SIZE);
    pt.extend(std::iter::repeat(pad_len as u8).take(pad_len));

    let cipher = Serpent::new_from_slice(&key)?;
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

    let mut mac = <HmacSha256 as hmac::digest::KeyInit>::new_from_slice(&hmac_key)
        .context("HMAC init failed")?;
    mac.update(&salt);
    mac.update(&iv);
    mac.update(&ct);
    let tag = mac.finalize().into_bytes();

    let mut out = Vec::with_capacity(salt.len() + iv.len() + ct.len() + tag.len());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&iv);
    out.extend_from_slice(&ct);
    out.extend_from_slice(&tag);
    Ok(out)
}

fn decrypt_file(data: &[u8], password: &str) -> Result<Vec<u8>> {
    if data.len() < SALT_LEN + BLOCK_SIZE + TAG_SIZE {
        anyhow::bail!("Data too short");
    }

    let salt = &data[..SALT_LEN];
    let iv = &data[SALT_LEN..SALT_LEN + BLOCK_SIZE];
    let tag = &data[data.len() - TAG_SIZE..];
    let ct = &data[SALT_LEN + BLOCK_SIZE..data.len() - TAG_SIZE];

    let key = derive_key(password, salt)?;
    let mut hasher = Sha256::new();
    hasher.update(&key);
    let hmac_key = hasher.finalize();

    let mut mac = <HmacSha256 as hmac::digest::KeyInit>::new_from_slice(&hmac_key)
        .context("HMAC init failed")?;
    mac.update(salt);
    mac.update(iv);
    mac.update(ct);
    mac.verify(tag.into()).context("HMAC verification failed")?;

    let cipher = Serpent::new_from_slice(&key)?;
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
