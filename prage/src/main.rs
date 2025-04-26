use std::{
    fs::{self, File},
    io::{BufReader, BufWriter, Write, copy},
    path::PathBuf,
};

use age::{Decryptor, Encryptor, secrecy::SecretString};
use age::scrypt::Identity;
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use rpassword::read_password;

#[derive(Parser)]
#[command(name = "prage", version, author, about = "🔐 Password-based file encryption")]
struct Cli {
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt a file
    Enc { input: PathBuf, output: PathBuf },
    /// Decrypt a file
    Dec { input: PathBuf, output: PathBuf },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Commands::Enc { input, output } => encrypt_file(&input, &output)?,
        Commands::Dec { input, output } => decrypt_file(&input, &output)?,
    }
    Ok(())
}

fn read_passphrase(confirm: bool) -> Result<SecretString> {
    eprint!("Enter passphrase: ");
    let first = read_password()?.trim().to_owned();
    if confirm {
        eprint!("Confirm passphrase: ");
        let second = read_password()?.trim().to_owned();
        if first != second {
            anyhow::bail!("❌ Passphrases do not match");
        }
    }
    Ok(SecretString::from(first))
}

fn encrypt_file(input: &PathBuf, output: &PathBuf) -> Result<()> {
    let pass = read_passphrase(true)?;
    let encryptor = Encryptor::with_user_passphrase(pass);
    let mut reader = BufReader::new(File::open(input)
        .with_context(|| format!("❌ Failed to open '{}'", input.display()))?);
    let tmp = output.with_extension("tmp");
    let mut writer = BufWriter::new(File::create(&tmp)
        .with_context(|| format!("❌ Failed to create '{}'", tmp.display()))?);

    let mut age_writer = encryptor.wrap_output(&mut writer)?;
    copy(&mut reader, &mut age_writer).context("❌ Encryption error")?;
    age_writer.finish().context("❌ Failed to finalize encryption")?;
    fs::rename(tmp, output).context("❌ Failed to rename output file")?;
    println!("✅ Encrypted → '{}'", output.display());
    Ok(())
}

fn decrypt_file(input: &PathBuf, output: &PathBuf) -> Result<()> {
    let pass = read_passphrase(false)?;
    let mut input_file = File::open(input)
        .with_context(|| format!("❌ Failed to open '{}'", input.display()))?;
    let decryptor = Decryptor::new(&mut input_file)
        .context("❌ Failed to parse age header")?;
    let mut age_reader = decryptor
        .decrypt(std::iter::once(&Identity::new(pass) as _))
        .context("❌ Decryption failed")?;

    let tmp = output.with_extension("tmp");
    let mut writer = BufWriter::new(File::create(&tmp)
        .with_context(|| format!("❌ Failed to create '{}'", tmp.display()))?);
    copy(&mut age_reader, &mut writer).context("❌ Decryption copy error")?;
    writer.flush().context("❌ Failed to flush writer")?;
    fs::rename(tmp, output).context("❌ Failed to rename output file")?;
    println!("✅ Decrypted → '{}'", output.display());
    Ok(())
}
