use clap::{Parser, ValueEnum};

#[derive(Parser)]
#[command(author, version, about)]
pub struct Cli {
    /// Key size for generation modes (e.g., 512KB, 1MB, 2GB)
    #[arg(value_name = "SIZE", required_if_eq("mode", "argon2"))]
    #[arg(required_if_eq("mode", "scrypt"))]
    #[arg(required_if_eq("mode", "pbkdf2"))]
    #[arg(required_if_eq("mode", "dualpass"))]
    #[arg(required_if_eq("mode", "xorprng"))]
    #[arg(required_if_eq("mode", "multikey"))]
    #[arg(required_if_eq("mode", "random"))]
    #[arg(help_heading = "Key Generation")]
    pub size: Option<String>,

    /// Generation or analysis mode
    #[arg(long, default_value = "argon2")]
    pub mode: Mode,

    /// Primary password
    #[arg(short = 'p', long = "password")]
    pub password: Option<String>,

    /// Secondary password (for dualpass mode)
    #[arg(long)]
    pub password2: Option<String>,

    /// Number of keys to generate
    #[arg(long)]
    pub count: Option<u32>,

    /// Show SHA-256 hash after generation
    #[arg(long)]
    pub checksum: bool,

    /// Input file for analysis mode (--mode entropy-test)
    #[arg(long, required_if_eq("mode", "entropy-test"))]
    pub input: Option<String>,

    /// Optional custom output filename (only used when --count=1)
    #[arg(long)]
    pub output: Option<String>,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
pub enum Mode {
    Argon2,
    Scrypt,
    Pbkdf2,
    DualPass,
    XorPrng,
    Random,
    MultiKey,
    EntropyTest,
}
