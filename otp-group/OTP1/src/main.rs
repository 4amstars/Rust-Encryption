
// [package]
//name = "otp1"
//version = "0.1.0"
//edition = "2024"

//[dependencies]

//tempfile   = "3.19.1"


use std::{
    env,
    fs,
    io::{self, BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
};
use tempfile::NamedTempFile;

const BUF_CAP: usize = 64 * 1024; // 64 KiB

fn main() -> io::Result<()> {
    let input_path = env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            eprintln!("Usage: {} <file-to-encrypt>", env::args().next().unwrap());
            std::process::exit(1);
        });

    // size check
    let data_len = fs::metadata(&input_path)?.len();
    let key_len  = fs::metadata("key.key")?.len();
    if key_len < data_len {
        eprintln!(
            "Key too short ({} bytes) for data ({} bytes).",
            key_len, data_len
        );
        std::process::exit(1);
    }

    // prepare readers/writer
    let mut data = BufReader::with_capacity(BUF_CAP, fs::File::open(&input_path)?);
    let mut key  = BufReader::with_capacity(BUF_CAP, fs::File::open("key.key")?);
    let tmp = NamedTempFile::new_in(input_path.parent().unwrap_or(Path::new(".")))?;
    let mut out = BufWriter::with_capacity(BUF_CAP, tmp.as_file());

    let mut data_buf = [0u8; BUF_CAP];
    let mut key_buf  = [0u8; BUF_CAP];

    // XOR loop
    while let Ok(n) = data.read(&mut data_buf) {
        if n == 0 { break; }
        key.read_exact(&mut key_buf[..n])?;
        for i in 0..n {
            data_buf[i] ^= key_buf[i];
        }
        out.write_all(&data_buf[..n])?;
    }

    out.flush()?;
    drop(out);   // close writer
    drop(data);  // close input file
    drop(key);   // close key file
    tmp.persist(&input_path)?; // now succeeds on Windows

    println!("Operation successful.");
    Ok(())
}
