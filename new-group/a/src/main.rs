use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Write};
use std::path::PathBuf;

use age::{Decryptor, Encryptor};
use age::x25519::{Identity, Recipient};
use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use indicatif::{ProgressBar, ProgressStyle};
use log::info;

#[derive(Parser)]
#[command(name = "a", version, author, about = "🔐 Production-safe age file encryptor.")]
struct Cli {
    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Encrypt {
        #[arg(short, long)]
        input: PathBuf,

        #[arg(short, long)]
        output: PathBuf,

        /// One or more recipient public keys
        #[arg(short, long)]
        recipient: Vec<String>,

        /// Overwrite existing output file
        #[arg(short, long)]
        force: bool,
    },

    Decrypt {
        #[arg(short, long)]
        input: PathBuf,

        #[arg(short, long)]
        output: PathBuf,

        #[arg(short, long)]
        key: PathBuf,

        /// Overwrite existing output file
        #[arg(short, long)]
        force: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    if cli.verbose {
        env_logger::init();
    }

    match cli.command {
        Commands::Encrypt { input, output, recipient, force } => {
            encrypt(input, output, recipient, force)
        }
        Commands::Decrypt { input, output, key, force } => {
            decrypt(input, output, key, force)
        }
    }
}

fn encrypt(input: PathBuf, output: PathBuf, recipient_strs: Vec<String>, force: bool) -> Result<()> {
    if output.exists() && !force {
        return Err(anyhow!("❌ Output file {} exists. Use --force to overwrite.", output.display()));
    }

    let mut recipients: Vec<Box<dyn age::Recipient>> = Vec::new();
    for r in recipient_strs {
        let rec = r.parse::<Recipient>()
            .map_err(|_| anyhow!("❌ Invalid recipient key: {}", r))?;
        recipients.push(Box::new(rec));
    }
    if recipients.is_empty() {
        return Err(anyhow!("❌ At least one recipient must be provided"));
    }

    let encryptor = Encryptor::with_recipients(recipients.iter().map(|r| r.as_ref()))
        .map_err(|e| anyhow!("❌ Failed to create encryptor: {}", e))?;

    let infile = File::open(&input)?;
    let outfile = File::create(&output)?;
    let metadata = infile.metadata()?;

    let pb = progress_bar(metadata.len())?;
    let mut reader = pb.wrap_read(BufReader::new(infile));
    let mut writer = encryptor.wrap_output(BufWriter::new(outfile))?;

    info!("Starting encryption of {}", input.display());
    std::io::copy(&mut reader, &mut writer)?;
    writer.finish()?;
    pb.finish_with_message("✅ Encrypted");
    Ok(())
}

fn decrypt(input: PathBuf, output: PathBuf, key_path: PathBuf, force: bool) -> Result<()> {
    if output.exists() && !force {
        return Err(anyhow!("❌ Output file {} exists. Use --force to overwrite.", output.display()));
    }

    let key_content = fs::read_to_string(&key_path)?;
    let identity_line = key_content
        .lines()
        .find(|line| line.starts_with("AGE-SECRET-KEY"))
        .ok_or_else(|| anyhow!("❌ No AGE-SECRET-KEY found in {}", key_path.display()))?;

    let identity = identity_line
        .parse::<Identity>()
        .map_err(|_| anyhow!("❌ Invalid identity key"))?;

    let infile = File::open(&input)?;
    let outfile = File::create(&output)?;
    let metadata = infile.metadata()?;

    let pb = progress_bar(metadata.len())?;
    let decryptor = Decryptor::new(BufReader::new(pb.wrap_read(infile)))?;

    let identities: Vec<Box<dyn age::Identity>> = vec![Box::new(identity)];
    let mut reader = decryptor.decrypt(identities.iter().map(|i| i.as_ref()))?;
    let mut writer = BufWriter::new(outfile);

    info!("Starting decryption of {}", input.display());
    std::io::copy(&mut reader, &mut writer)?;
    writer.flush()?; // ensure all bytes are written
    pb.finish_with_message("✅ Decrypted");
    Ok(())
}

fn progress_bar(len: u64) -> Result<ProgressBar> {
    let pb = ProgressBar::new(len);
    let style = ProgressStyle::with_template(
        "[{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})",
    ).map_err(|e| anyhow!("❌ Invalid progress bar template: {}", e))?;
    pb.set_style(style);
    Ok(pb)
}
