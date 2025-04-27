// src/main.rs
mod args;
mod encrypt;
mod files;

use std::{error::Error, process};
use args::Args;

fn main() {
    let args = match Args::arguments(std::env::args()) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{}", e);
            process::exit(1);
        }
    };
    if let Err(e) = run(args) {
        eprintln!("Error: {}", e);
        process::exit(1);
    }
}

pub fn run(args: Args) -> Result<(), Box<dyn Error>> {
    let cipher = encrypt::Cipher::new(&args.password);
    let filepaths = files::get_filepaths(args.input_path, args.output_path)?;
    for p in filepaths {
        let data = files::read_file(&p.input_path)?;
        let out = cipher.apply_codec(data, &args.codec_type);
        files::write_file(&p.output_path, out)?;
    }
    Ok(())
}
