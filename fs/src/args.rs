// src/args.rs
use clap::{Parser, ValueEnum};
use std::path::PathBuf;

#[derive(Parser)]
#[command(author, version, about)]
pub struct Args {
    #[arg(value_enum)]
    pub codec_type: CodecType,
    pub input_path: PathBuf,
    pub output_path: PathBuf,
    #[arg(short, long)]
    pub password: String,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
pub enum CodecType {
    Encrypt,
    Decrypt,
}

impl Args {
    pub fn arguments<I>(itr: I) -> Result<Self, &'static str>
    where
        I: Iterator<Item = String>,
    {
        Args::try_parse_from(itr).map_err(|_| "Invalid arguments")
    }
}
