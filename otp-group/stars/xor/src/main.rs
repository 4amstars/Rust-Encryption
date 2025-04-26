use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write, BufReader, BufWriter};
use std::path::Path;
use atomic_write_file::AtomicWriteFile;
use sys_info;
use zeroize::Zeroize;
use chrono::Utc;
use sha2::{Digest, Sha256};

fn get_chunk_size() -> usize {
    const MAX_ALLOWED: usize = 4 * 1024 * 1024 * 1024;
    const RESERVE: usize = 512 * 1024 * 1024;

    match sys_info::mem_info() {
        Ok(mem) => {
            let available = (mem.total * 1024) as usize;
            let target = (available / 4).min(MAX_ALLOWED);
            (target - RESERVE) / 2
        }
        Err(_) => {
            log_error("⚠️ Failed to detect system RAM. Using fallback chunk size of 64 KiB.");
            64 * 1024
        }
    }
}

fn log_error(msg: &str) {
    eprintln!("{}", msg);
    let timestamp = Utc::now().to_rfc3339();
    let formatted = format!("[{}] {}", timestamp, msg);

    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open("error.txt")
    {
        let _ = writeln!(file, "{}", formatted);
    }
}

fn hash_file(path: &str) -> io::Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    let mut reader = BufReader::new(File::open(path)?);
    let mut buf = [0u8; 8192];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 { break; }
        hasher.update(&buf[..n]);
    }
    let hash = hasher.finalize();
    Ok(hash.into())
}

fn xor_files_atomic(input_path: &str, key_path: &str, output_path: &str) -> io::Result<()> {
    let input_metadata = std::fs::metadata(input_path)?;
    let key_metadata = std::fs::metadata(key_path)?;

    if key_metadata.len() < input_metadata.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "Key file ({}) is smaller than input file ({}).",
                key_metadata.len(),
                input_metadata.len()
            ),
        ));
    }

    let chunk_size = get_chunk_size();

    let mut input = BufReader::new(File::open(input_path)?);
    let mut key = BufReader::new(File::open(key_path)?);
    let mut atomic = AtomicWriteFile::options().open(output_path)?;

    let mut buf_input = vec![0u8; chunk_size];
    let mut buf_key = vec![0u8; chunk_size];

    {
        let mut writer = BufWriter::new(atomic.as_file_mut());

        loop {
            let n_input = input.read(&mut buf_input)?;
            let n_key = key.read(&mut buf_key)?; // might be larger; fine
            if n_input == 0 {
                break;
            }

            for i in 0..n_input {
                buf_input[i] ^= buf_key[i];
            }

            writer.write_all(&buf_input[..n_input])?;
            buf_key[..n_key].zeroize();
        }

        writer.flush()?;
    }

    atomic.commit()?;
    Ok(())
}

fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        log_error("Usage: xor <input_file> <key_file> <output_file>");
        std::process::exit(1);
    }

    let input = &args[1];
    let key = &args[2];
    let output = &args[3];

    if [input, key].contains(&output) {
        log_error("❌ Output file must not be the same as input or key file.");
        std::process::exit(1);
    }

    if Path::new(output).exists() {
        log_error(&format!(
            "❌ Output file '{}' already exists. Aborting to avoid overwrite.",
            output
        ));
        std::process::exit(1);
    }

    let input_hash = match hash_file(input) {
        Ok(hash) => hash,
        Err(e) => {
            log_error(&format!("❌ Failed to hash input file: {}", e));
            std::process::exit(1);
        }
    };

    if let Err(e) = xor_files_atomic(input, key, output) {
        log_error(&format!("❌ XOR operation failed: {}", e));
        std::process::exit(1);
    }

    // Re-XOR to verify output correctness
    let recon_path = format!("{}.recheck.tmp", output);
    if let Err(e) = xor_files_atomic(output, key, &recon_path) {
        log_error(&format!("❌ Verification step failed: {}", e));
        std::process::exit(1);
    }

    let recon_hash = match hash_file(&recon_path) {
        Ok(hash) => hash,
        Err(e) => {
            log_error(&format!("❌ Failed to hash reconstructed file: {}", e));
            std::process::exit(1);
        }
    };

    if input_hash == recon_hash {
        let _ = std::fs::remove_file(&recon_path);
        println!("✅ File verified successfully 🔒");
    } else {
        println!("❌ Verification failed! Output may be corrupted.");
        println!("⚠️  Reconstructed file saved as '{}'", recon_path);
        log_error("❌ Hash mismatch after verification step.");
    }

    Ok(())
}
