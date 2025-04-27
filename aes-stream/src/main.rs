// src/main.rs

use clap::{Parser, Subcommand};
use std::{
    fs::{self, File},
    io::{self, copy},
    process,
};
use tink_core::{
    keyset::{
        Handle,
        BinaryWriter,
        BinaryReader,
        insecure::{write as write_keyset, read as read_keyset},
    },
};
use tink_streaming_aead as streaming_aead;

// (Empty AAD—authenticated but not encrypted data)
const AAD: &[u8] = b"";

#[derive(Parser)]
#[command(author, version, about = "Stream-chunked AEAD encryption/decryption using Tink")]
struct Cli {
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Encrypt {
        /// Path to plaintext input
        input: String,
        /// Path to encrypted output
        output: String,
        /// Where to store the cleartext keyset
        key_file: String,
    },
    Decrypt {
        /// Path to encrypted input
        input: String,
        /// Path to decrypted output
        output: String,
        /// Where to read the cleartext keyset
        key_file: String,
    },
}

fn main() {
    if let Err(e) = run() {
        let _ = fs::write("error.txt", format!("{:?}", e));
        eprintln!("Error: {:?}. Details in error.txt", e);
        process::exit(1);
    }
}

fn run() -> io::Result<()> {
    // Register the streaming-AEAD algorithms
    streaming_aead::init();

    let cli = Cli::parse();
    match cli.cmd {
        Commands::Encrypt { input, output, key_file } =>
            encrypt(&input, &output, &key_file),
        Commands::Decrypt { input, output, key_file } =>
            decrypt(&input, &output, &key_file),
    }
}

fn encrypt(input: &str, output: &str, key_file: &str) -> io::Result<()> {
    // 1) Generate a new keyset handle (4 KB-segment AES-GCM-HKDF)
    let kh: Handle = Handle::new(
        &streaming_aead::aes128_gcm_hkdf_4kb_key_template()
    ).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{:?}", e)))?;

    // 2) Write the cleartext keyset to disk (insecure!)
    let mut key_out = File::create(key_file)?;
    let mut bw = BinaryWriter::new(&mut key_out);
    write_keyset(&kh, &mut bw)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{:?}", e)))?;

    // 3) Get the StreamingAead primitive
    let primitive = streaming_aead::new(&kh)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{:?}", e)))?;

    // 4) Stream-encrypt via the Write adapter
    let mut reader = File::open(input)?;
    let writer = File::create(output)?;
    let mut enc_writer = primitive
        .new_encrypting_writer(Box::new(writer), AAD)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{:?}", e)))?;
    copy(&mut reader, &mut enc_writer)?;
    enc_writer.close()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{:?}", e)))?;

    Ok(())
}

fn decrypt(input: &str, output: &str, key_file: &str) -> io::Result<()> {
    // 1) Read and parse the cleartext keyset
    let mut key_in = File::open(key_file)?;
    let mut br = BinaryReader::new(&mut key_in);
    let kh: Handle = read_keyset(&mut br)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{:?}", e)))?;

    // 2) Get the StreamingAead primitive
    let primitive = streaming_aead::new(&kh)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{:?}", e)))?;

    // 3) Stream-decrypt via the Read adapter
    let reader = File::open(input)?;
    let mut dec_reader = primitive
        .new_decrypting_reader(Box::new(reader), AAD)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{:?}", e)))?;
    let mut writer = File::create(output)?;
    copy(&mut dec_reader, &mut writer)?;

    Ok(())
}
