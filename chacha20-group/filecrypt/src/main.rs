use std::{
    fs::{self, File},
    io::{self, Read, Write, BufReader},
    path::Path,
    process,
    time::SystemTime,
};

use clap::Parser;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use chacha20poly1305::aead::rand_core::{OsRng, RngCore};
use tempfile::NamedTempFile;
use zeroize::Zeroizing;

const MAGIC: &[u8; 6] = b"FCRYPT";
const VERSION: u8 = 1;
const NONCE_SIZE: usize = 24;
const KEY_SIZE: usize = 32;
const CHUNK_SIZE: usize = 64 * 1024;

/// FileCrypt: Simple and secure file encryption using XChaCha20-Poly1305
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// File to encrypt or decrypt automatically
    file: String,
}

fn main() {
    if let Err(e) = try_main() {
        log_error("fatal", &e.to_string());
        eprintln!("Error: {e}");
        process::exit(1);
    }
}

fn try_main() -> io::Result<()> {
    let cli = Cli::parse();
    let path = Path::new(&cli.file);

    let key = load_key("key.key")?;

    if detect_encrypted(path)? {
        println!("Detected encrypted file. Decrypting...");
        decrypt_file(path, &key)
    } else {
        println!("Detected plaintext file. Encrypting...");
        encrypt_file(path, &key)
    }
}

fn load_key(path: &str) -> io::Result<Zeroizing<[u8; KEY_SIZE]>> {
    let key_data = fs::read(path).map_err(|e| {
        log_error("load_key", &format!("Failed to read '{}': {}", path, e));
        e
    })?;

    if key_data.len() != KEY_SIZE {
        let err = format!("Invalid key length: expected {} bytes, got {}", KEY_SIZE, key_data.len());
        log_error("load_key", &err);
        return Err(io::Error::new(io::ErrorKind::InvalidData, err));
    }

    let mut key = [0u8; KEY_SIZE];
    key.copy_from_slice(&key_data);
    Ok(Zeroizing::new(key))
}

fn detect_encrypted(path: &Path) -> io::Result<bool> {
    let mut f = File::open(path).map_err(|e| {
        log_error("detect_encrypted", &format!("Failed to open file '{}': {}", path.display(), e));
        e
    })?;
    let mut magic = [0u8; MAGIC.len()];
    match f.read_exact(&mut magic) {
        Ok(_) => Ok(&magic == MAGIC),
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(false),
        Err(e) => {
            log_error("detect_encrypted", &format!("Failed to read magic: {}", e));
            Err(e)
        }
    }
}

fn encrypt_file(path: &Path, key: &[u8; KEY_SIZE]) -> io::Result<()> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let tmp = NamedTempFile::new_in(path.parent().unwrap()).map_err(|e| {
        log_error("encrypt", &format!("Failed to create temp file: {}", e));
        e
    })?;

    let input_file = File::open(path).map_err(|e| {
        log_error("encrypt", &format!("Failed to open input file '{}': {}", path.display(), e));
        e
    })?;
    let mut input = BufReader::new(input_file);
    let mut output = tmp.reopen().map_err(|e| {
        log_error("encrypt", &format!("Failed to reopen temp file: {}", e));
        e
    })?;

    let mut nonce = [0u8; NONCE_SIZE];
    let mut rng = OsRng;
    rng.fill_bytes(&mut nonce);

    output.write_all(MAGIC)?;
    output.write_all(&[VERSION])?;
    output.write_all(&nonce)?;

    let mut buf = [0u8; CHUNK_SIZE];
    let mut chunk_index = 0u64;

    loop {
        let n = input.read(&mut buf)?;
        if n == 0 {
            break;
        }

        if chunk_index == u64::MAX {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Too many chunks — nonce space exhausted",
            ));
        }

        let chunk_nonce = derive_chunk_nonce(&nonce, chunk_index);
        let ciphertext = cipher
            .encrypt(&chunk_nonce, &buf[..n])
            .map_err(|e| {
                log_error("encrypt", &format!("Encryption failed: {}", e));
                io::Error::new(io::ErrorKind::Other, "Encryption failed")
            })?;

        output.write_all(&(ciphertext.len() as u32).to_be_bytes())?;
        output.write_all(&ciphertext)?;
        chunk_index += 1;
    }

    output.sync_all()?;
    drop(input);
    tmp.persist(path).map_err(|e| {
        log_error("encrypt", &format!("Failed to persist temp file: {}", e));
        e.error
    })?;

    println!("Encryption complete.");
    Ok(())
}

fn decrypt_file(path: &Path, key: &[u8; KEY_SIZE]) -> io::Result<()> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let tmp = NamedTempFile::new_in(path.parent().unwrap()).map_err(|e| {
        log_error("decrypt", &format!("Failed to create temp file: {}", e));
        e
    })?;

    let input_file = File::open(path)?;
    let mut input = BufReader::new(input_file);
    let mut output = tmp.reopen()?;

    let mut magic = [0u8; 6];
    input.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid magic header"));
    }

    let mut version = [0u8; 1];
    input.read_exact(&mut version)?;
    if version[0] != VERSION {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Unsupported version"));
    }

    let mut nonce = [0u8; NONCE_SIZE];
    input.read_exact(&mut nonce)?;

    let mut chunk_index = 0u64;

    loop {
        if chunk_index == u64::MAX {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Too many chunks — nonce space exhausted",
            ));
        }

        let mut len_buf = [0u8; 4];
        match input.read_exact(&mut len_buf) {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        }

        let chunk_len = u32::from_be_bytes(len_buf) as usize;
        let mut ciphertext = vec![0u8; chunk_len];
        input.read_exact(&mut ciphertext)?;

        let chunk_nonce = derive_chunk_nonce(&nonce, chunk_index);
        let plaintext = cipher
            .decrypt(&chunk_nonce, ciphertext.as_slice())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Decryption failed"))?;

        output.write_all(&plaintext)?;
        chunk_index += 1;
    }

    output.sync_all()?;
    drop(input);
    tmp.persist(path).map_err(|e| {
        log_error("decrypt", &format!("Failed to persist temp file: {}", e));
        e.error
    })?;

    println!("Decryption complete.");
    Ok(())
}

fn derive_chunk_nonce(base: &[u8; NONCE_SIZE], index: u64) -> XNonce {
    let mut nonce = [0u8; NONCE_SIZE];
    nonce[..NONCE_SIZE - 8].copy_from_slice(&base[..NONCE_SIZE - 8]);
    nonce[NONCE_SIZE - 8..].copy_from_slice(&index.to_be_bytes());
    XNonce::from_slice(&nonce).clone()
}

/// Logs detailed errors to `error.txt` in the same folder as the binary.
fn log_error(source: &str, message: &str) {
    let now = SystemTime::now();
    let timestamp = format!("{:?}", now);

    let log_msg = format!("[{timestamp}] [{source}] {message}\n");

    if let Ok(mut file) = File::options()
        .append(true)
        .create(true)
        .open("error.txt")
    {
        let _ = file.write_all(log_msg.as_bytes());
    }
}
