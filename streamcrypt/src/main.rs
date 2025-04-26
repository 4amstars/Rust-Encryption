use std::{
    fs::File,
    io::{BufReader, BufWriter, Read, Write},
    path::Path,
};

use clap::{Parser, Subcommand};
use rand::{rngs::OsRng, RngCore};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::{Aead, Payload};
use tink_core::keyset::{BinaryReader, BinaryWriter, Handle, insecure};
use tink_streaming_aead::{init as init_stream, new as new_stream, aes256_gcm_hkdf_1mb_key_template};
use argon2::Argon2;
use byteorder::{ReadBytesExt, WriteBytesExt, BigEndian};

#[derive(Parser)]
#[command(author, version, about = "streamcrypt v3 – secure, streaming encryption with password-protected keysets")]
struct Cli {
    #[arg(long)]
    passphrase: Option<String>,

    #[arg(long)]
    keyset: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new keyset and encrypt it with a password
    Keygen,

    /// Encrypt a file using an external password-encrypted keyset
    Encrypt {
        input: String,
        output: String,
    },

    /// Decrypt a file using an external password-encrypted keyset
    Decrypt {
        input: String,
        output: String,
    },
}

fn derive_argon2_key(pass: &str, salt: &[u8]) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(pass.as_bytes(), salt, &mut key)
        .map_err(|e| format!("argon2 error: {e}"))?;
    Ok(key)
}

fn save_encrypted_keyset(
    handle: &Handle,
    pass: &str,
    ks_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut ks_buf = Vec::new();
    {
        let mut writer = BinaryWriter::new(&mut ks_buf);
        insecure::write(handle, &mut writer)?;
    }

    let mut salt = [0u8; 16]; OsRng.fill_bytes(&mut salt);
    let mut nonce = [0u8; 12]; OsRng.fill_bytes(&mut nonce);
    let kek = derive_argon2_key(pass, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&kek)?;
    let ciphertext = cipher.encrypt(Nonce::from_slice(&nonce), Payload { msg: &ks_buf, aad: &[] })?;

    let mut file = File::create(ks_path)?;
    file.write_all(&salt)?;
    file.write_all(&nonce)?;
    file.write_u32::<BigEndian>(ciphertext.len() as u32)?;
    file.write_all(&ciphertext)?;
    Ok(())
}

fn load_encrypted_keyset(
    pass: &str,
    ks_path: &Path,
) -> Result<Handle, Box<dyn std::error::Error>> {
    let mut file = File::open(ks_path)?;
    let mut salt = [0u8; 16]; file.read_exact(&mut salt)?;
    let mut nonce = [0u8; 12]; file.read_exact(&mut nonce)?;
    let len = file.read_u32::<BigEndian>()? as usize;
    let mut ciphertext = vec![0u8; len];
    file.read_exact(&mut ciphertext)?;

    let kek = derive_argon2_key(pass, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&kek)?;
    let plaintext = cipher.decrypt(Nonce::from_slice(&nonce), Payload { msg: &ciphertext, aad: &[] })?;
    let mut reader = BinaryReader::new(std::io::Cursor::new(plaintext));
    let handle = insecure::read(&mut reader)?;
    Ok(handle)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_stream();
    let cli = Cli::parse();

    match &cli.command {
        Commands::Keygen => {
            let pass = cli.passphrase.as_ref().ok_or("Missing --passphrase")?;
            let ks_path = Path::new(&cli.keyset);
            let handle = Handle::new(&aes256_gcm_hkdf_1mb_key_template())?;
            save_encrypted_keyset(&handle, pass, ks_path)?;
            println!("🔐 Keyset saved to {}", ks_path.display());
        }

        Commands::Encrypt { input, output } => {
            let pass = cli.passphrase.as_ref().ok_or("Missing --passphrase")?;
            let ks_path = Path::new(&cli.keyset);
            let handle = load_encrypted_keyset(pass, ks_path)?;
            let streaming_aead = new_stream(&handle)?;

            let input: Box<dyn Read> = if input == "-" {
                Box::new(std::io::stdin())
            } else {
                Box::new(BufReader::new(File::open(input)?))
            };

            let output: Box<dyn Write> = if output == "-" {
                Box::new(std::io::stdout())
            } else {
                Box::new(BufWriter::new(File::create(output)?))
            };

            let mut enc_writer = streaming_aead.new_encrypting_writer(output, &[])?;
            std::io::copy(&mut BufReader::new(input), &mut enc_writer)?;
            enc_writer.close()?;
        }

        Commands::Decrypt { input, output } => {
            let pass = cli.passphrase.as_ref().ok_or("Missing --passphrase")?;
            let ks_path = Path::new(&cli.keyset);
            let handle = load_encrypted_keyset(pass, ks_path)?;
            let streaming_aead = new_stream(&handle)?;

            let input: Box<dyn Read> = if input == "-" {
                Box::new(std::io::stdin())
            } else {
                Box::new(BufReader::new(File::open(input)?))
            };

            let mut output: Box<dyn Write> = if output == "-" {
                Box::new(std::io::stdout())
            } else {
                Box::new(BufWriter::new(File::create(output)?))
            };

            let mut dec_reader = streaming_aead.new_decrypting_reader(input, &[])?;
            std::io::copy(&mut dec_reader, &mut output)?;
        }
    }

    Ok(())
}
