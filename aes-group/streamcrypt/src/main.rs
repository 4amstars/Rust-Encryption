use std::{
    fs::File,
    io::{BufReader, BufWriter, Read, Write},
    path::Path,
};
use clap::{Parser, Subcommand};
use pbkdf2::pbkdf2;
use hmac::Hmac;
use sha2::Sha256;
use rand::{RngCore, rngs::OsRng};
use zeroize::Zeroize;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::{Aead, Payload};
use tink_core::keyset::{BinaryReader, BinaryWriter, Handle, insecure};
use tink_streaming_aead::{init as init_stream, new as new_stream, aes256_gcm_hkdf_4kb_key_template};
use argon2::Argon2;
use rpassword::read_password;

type HmacSha256 = Hmac<Sha256>;

const MAGIC: &[u8; 4] = b"SCRY";
const VERSION: u8 = 1;

#[derive(Parser)]
#[command(author, version, about = "streamcrypt v2: Self-contained streaming encryption with password or keyset.")]
struct Cli {
    #[arg(long)]
    nokey: bool,

    #[arg(long, env = "KEYSET_PATH", default_value = "a.k")]
    keyset: String,

    #[arg(long, env = "KEYSET_PASSPHRASE")]
    passphrase: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Keygen,
    Encrypt { input: String, output: String },
    Decrypt { input: String, output: String },
}

fn read_password_twice() -> Result<String, Box<dyn std::error::Error>> {
    println!("Enter password:");
    let p1 = read_password()?;
    println!("Confirm password:");
    let p2 = read_password()?;
    if p1 != p2 {
        return Err("Passwords do not match".into());
    }
    Ok(p1)
}

fn derive_argon2_key(pass: &str, salt: &[u8]) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let argon2 = Argon2::default();
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(pass.as_bytes(), salt, &mut key)
        .map_err(|e| format!("argon2 error: {e}"))?;
    Ok(key)
}

fn derive_kek(pass: &str, salt: &[u8]) -> [u8; 32] {
    let mut kek = [0u8; 32];
    let iterations = 100_000;
    pbkdf2::<HmacSha256>(pass.as_bytes(), salt, iterations, &mut kek);
    kek
}

fn save_encrypted_keyset(
    handle: &Handle,
    pass: &str,
    ks_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut clear_buf = Vec::new();
    {
        let mut w = BinaryWriter::new(&mut clear_buf);
        insecure::write(handle, &mut w)?;
    }
    let mut salt = [0u8; 16]; OsRng.fill_bytes(&mut salt);
    let mut nonce = [0u8; 12]; OsRng.fill_bytes(&mut nonce);
    let kek = derive_kek(pass, &salt);
    let cipher = Aes256Gcm::new_from_slice(&kek)?;
    let ciphertext = cipher.encrypt(Nonce::from_slice(&nonce), clear_buf.as_ref())?;
    let mut out = File::create(ks_path)?;
    out.write_all(&salt)?;
    out.write_all(&nonce)?;
    out.write_all(&ciphertext)?;
    clear_buf.zeroize();
    Ok(())
}

fn load_encrypted_keyset(
    pass: &str,
    ks_path: &Path,
) -> Result<Handle, Box<dyn std::error::Error>> {
    let mut f = File::open(ks_path)?;
    let mut salt = [0u8; 16]; f.read_exact(&mut salt)?;
    let mut nonce = [0u8; 12]; f.read_exact(&mut nonce)?;
    let mut ciphertext = Vec::new(); f.read_to_end(&mut ciphertext)?;
    let kek = derive_kek(pass, &salt);
    let cipher = Aes256Gcm::new_from_slice(&kek)?;
    let clear = cipher.decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())?;
    let mut reader = BinaryReader::new(std::io::Cursor::new(clear));
    let handle = insecure::read(&mut reader)?;
    Ok(handle)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_stream();
    let cli = Cli::parse();

    match &cli.command {
        Commands::Keygen if cli.nokey => {
            return Err("Keygen not allowed in --nokey mode".into());
        }

        Commands::Keygen => {
            let pass = cli.passphrase.as_ref().ok_or("Missing --passphrase")?;
            let ks_path = Path::new(&cli.keyset);
            let handle = Handle::new(&aes256_gcm_hkdf_4kb_key_template())?;
            save_encrypted_keyset(&handle, pass, ks_path)?;
            println!("Keyset saved to {}", ks_path.display());
            return Ok(());
        }

        Commands::Encrypt { input, output } |
        Commands::Decrypt { input, output } => {
            let reader: Box<dyn Read> = if input == "-" {
                Box::new(std::io::stdin())
            } else {
                Box::new(BufReader::new(File::open(input)?))
            };

            let mut writer: Box<dyn Write> = if output == "-" {
                Box::new(std::io::stdout())
            } else {
                Box::new(BufWriter::new(File::create(output)?))
            };

            if cli.nokey {
                if let Commands::Encrypt { .. } = &cli.command {
                    let pass = read_password_twice()?;
                    let mut salt = [0u8; 16]; OsRng.fill_bytes(&mut salt);
                    let mut nonce = [0u8; 12]; OsRng.fill_bytes(&mut nonce);
                    let key = derive_argon2_key(&pass, &salt)?;
                    let cipher = Aes256Gcm::new_from_slice(&key)?;
                    let nonce = Nonce::from_slice(&nonce);
                    let mut buf = Vec::new();
                    BufReader::new(reader).read_to_end(&mut buf)?;
                    let ciphertext = cipher.encrypt(nonce, Payload { msg: &buf, aad: &[] })?;
                    writer.write_all(MAGIC)?;
                    writer.write_all(&[VERSION])?;
                    writer.write_all(&salt)?;
                    writer.write_all(&nonce)?;
                    writer.write_all(&ciphertext)?;
                } else {
                    println!("Enter password:");
                    let pass = read_password()?;
                    let mut reader = BufReader::new(reader);

                    let mut magic = [0u8; 4]; reader.read_exact(&mut magic)?;
                    if &magic != MAGIC {
                        return Err("Invalid file format (missing SCRY magic)".into());
                    }

                    let mut version = [0u8; 1]; reader.read_exact(&mut version)?;
                    if version[0] != VERSION {
                        return Err("Unsupported file version".into());
                    }

                    let mut salt = [0u8; 16]; reader.read_exact(&mut salt)?;
                    let mut nonce = [0u8; 12]; reader.read_exact(&mut nonce)?;

                    let key = derive_argon2_key(&pass, &salt)?;
                    let cipher = Aes256Gcm::new_from_slice(&key)?;
                    let nonce = Nonce::from_slice(&nonce);
                    let mut buf = Vec::new();
                    reader.read_to_end(&mut buf)?;
                    let plaintext = cipher.decrypt(nonce, Payload { msg: &buf, aad: &[] })?;
                    writer.write_all(&plaintext)?;
                }
                return Ok(());
            }

            let pass = cli.passphrase.as_ref().ok_or("Missing --passphrase")?;
            let ks_path = Path::new(&cli.keyset);
            let handle = load_encrypted_keyset(pass, ks_path)?;
            let streaming_aead = new_stream(&handle)?;

            match &cli.command {
                Commands::Encrypt { .. } => {
                    let mut enc = streaming_aead.new_encrypting_writer(writer, &[])?;
                    std::io::copy(&mut BufReader::new(reader), &mut enc)?;
                    enc.close()?;
                }
                Commands::Decrypt { .. } => {
                    let mut dec = streaming_aead.new_decrypting_reader(reader, &[])?;
                    std::io::copy(&mut dec, &mut writer)?;
                }
                _ => unreachable!(),
            }
        }
    }

    Ok(())
}
