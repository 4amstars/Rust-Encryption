// src/files.rs
use std::{fs, io};
use std::path::{PathBuf, Path};

pub struct FilePair {
    pub input_path: PathBuf,
    pub output_path: PathBuf,
}

pub fn get_filepaths(input: PathBuf, output: PathBuf) -> io::Result<Vec<FilePair>> {
    // stub: treat input as a single file
    Ok(vec![FilePair { input_path: input, output_path: output }])
}

pub fn read_file(p: &Path) -> io::Result<Vec<u8>> {
    fs::read(p)
}

pub fn write_file(p: &Path, data: Vec<u8>) -> io::Result<()> {
    if let Some(dir) = p.parent() {
        fs::create_dir_all(dir)?;
    }
    fs::write(p, data)
}
