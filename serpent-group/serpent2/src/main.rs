


// src/main.rs

use clap::{Parser, Subcommand};
use std::{fs, path::PathBuf, convert::TryInto};
use anyhow::{Context, Result};
use rand::{rngs::OsRng, RngCore};
use serpent::Serpent;
use serpent::cipher::{BlockEncrypt, BlockDecrypt, KeyInit as SerpentKeyInit};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use hkdf::Hkdf;
use argon2::{Argon2, PasswordHasher, Params};
use argon2::password_hash::SaltString;
use rpassword::prompt_password;
use secrecy::{Secret, ExposeSecret};
use log::info;

const SALT_LEN: usize = 16;
const IV_LEN: usize = 16;
const TAG_LEN: usize = 32;

type HmacSha256 = Hmac<Sha256>;

#[derive(Parser)]
#[command(name = "serpent", version)]
struct Cli {
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Encrypt {
        #[arg(short, long)]
        input: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    Decrypt {
        #[arg(short, long)]
        input: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    match cli.cmd {
        Commands::Encrypt { input, output } => {
            info!("Encrypting {:?}", input);
            let pwd = prompt_password("Enter password: ")?;
            let salt = random_bytes(SALT_LEN);
            let key = derive_key(&pwd, &salt)?;
            let (k_enc, k_auth) = derive_subkeys(&key)?;

            let data = fs::read(&input).context("reading input file")?;
            let ciphertext = encrypt(&data, &salt, &k_enc, &k_auth)?;

            let out = output.unwrap_or_else(|| input.with_extension("enc"));
            fs::write(&out, ciphertext).context("writing output file")?;
            info!("Written to {:?}", out);
            Ok(())
        }
        Commands::Decrypt { input, output } => {
            info!("Decrypting {:?}", input);
            let pwd = prompt_password("Enter password: ")?;
            let data = fs::read(&input).context("reading input file")?;
            let out_data = decrypt(&data, &pwd)?;

            let out = output.unwrap_or_else(|| input.with_extension("dec"));
            fs::write(&out, out_data).context("writing output file")?;
            info!("Written to {:?}", out);
            Ok(())
        }
    }
}

fn random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0; len];
    OsRng.fill_bytes(&mut buf);
    buf
}

fn derive_key(pw: &str, salt: &[u8]) -> Result<Secret<[u8; 32]>> {
    let params = Params::new(15000, 3, 1, None).unwrap();
    // encode salt for Argon2
    let salt_str = SaltString::encode_b64(salt)
        .map_err(|e| anyhow::anyhow!("salt encoding failed: {}", e))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let hash = argon2
        .hash_password(pw.as_bytes(), &salt_str)
        .map_err(|e| anyhow::anyhow!("password hashing failed: {}", e))?;
    // ensure hash lives long enough
    let digest = hash.hash.ok_or_else(|| anyhow::anyhow!("Argon2 hash missing"))?;
    let raw = digest.as_bytes();

    let mut key = [0u8; 32];
    key.copy_from_slice(&raw[0..32]);
    Ok(Secret::new(key))
}

fn derive_subkeys(master: &Secret<[u8; 32]>) -> Result<(Vec<u8>, Vec<u8>)> {
    let hk = Hkdf::<Sha256>::new(None, master.expose_secret());
    let mut k_enc = vec![0u8; 32];
    let mut k_auth = vec![0u8; 32];
    hk.expand(b"enc", &mut k_enc).unwrap();
    hk.expand(b"auth", &mut k_auth).unwrap();
    Ok((k_enc, k_auth))
}

fn encrypt(plaintext: &[u8], salt: &[u8], k_enc: &[u8], k_auth: &[u8]) -> Result<Vec<u8>> {
    let iv = random_bytes(IV_LEN);
    let pad = IV_LEN - (plaintext.len() % IV_LEN);
    let mut buf = plaintext.to_vec();
    buf.extend(std::iter::repeat(pad as u8).take(pad));

    let cipher = Serpent::new_from_slice(k_enc)?;
    let mut ct = Vec::with_capacity(buf.len());
    let mut prev = iv.clone();
    for block in buf.chunks(IV_LEN) {
        let mut tmp = [0u8; IV_LEN];
        for i in 0..IV_LEN { tmp[i] = block[i] ^ prev[i]; }
        let mut bl = serpent::cipher::Block::<Serpent>::clone_from_slice(&tmp);
        cipher.encrypt_block(&mut bl);
        let e = bl.to_vec();
        prev.copy_from_slice(&e);
        ct.extend_from_slice(&e);
    }

    let mut mac = <HmacSha256 as Mac>::new_from_slice(k_auth).unwrap();
    mac.update(salt);
    mac.update(&iv);
    mac.update(&ct);
    let tag = mac.finalize().into_bytes();

    Ok([salt, &iv, &ct, &tag].concat())
}

fn decrypt(data: &[u8], pw: &str) -> Result<Vec<u8>> {
    if data.len() < SALT_LEN + IV_LEN + TAG_LEN {
        anyhow::bail!("data too short");
    }
    let salt = &data[..SALT_LEN];
    let iv_slice = &data[SALT_LEN..SALT_LEN+IV_LEN];
    let tag = &data[data.len()-TAG_LEN..];
    let ct = &data[SALT_LEN+IV_LEN..data.len()-TAG_LEN];

    let master = derive_key(pw, salt)?;
    let (k_enc, k_auth) = derive_subkeys(&master)?;

    let mut mac = <HmacSha256 as Mac>::new_from_slice(&k_auth).unwrap();
    mac.update(salt);
    mac.update(iv_slice);
    mac.update(ct);
    mac.verify_slice(tag).context("HMAC mismatch")?;

    let cipher = Serpent::new_from_slice(&k_enc)?;
    let mut pt = Vec::with_capacity(ct.len());
    let mut prev: [u8; IV_LEN] = iv_slice.try_into().unwrap();

    for chunk in ct.chunks(IV_LEN) {
        let mut bl = serpent::cipher::Block::<Serpent>::clone_from_slice(chunk);
        cipher.decrypt_block(&mut bl);
        let db = bl.to_vec();
        for i in 0..IV_LEN {
            pt.push(db[i] ^ prev[i]);
        }
        prev.copy_from_slice(chunk);
    }

    let pad = *pt.last().unwrap() as usize;
    pt.truncate(pt.len() - pad);
    Ok(pt)
}

