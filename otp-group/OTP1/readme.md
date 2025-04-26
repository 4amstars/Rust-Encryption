# OTP Streamer

A simple, cross-platform, chunked-streaming one-time pad (OTP) encryption/decryption utility written in Rust. It processes both the data file and key file in fixed-size (64 KiB) buffers, guaranteeing bounded memory usage and reliable, portable I/O.

## Features

- **Chunked Streaming**: Uses `BufReader`/`BufWriter` with 64 KiB buffers to avoid loading entire files into memory.
- **One-Time Pad**: Requires the key file to be at least as large as the data file for perfect secrecy.
- **Cross-Platform Atomic Writes**: Safely overwrite the input file via a temporary file + rename, with explicit handle closure on Windows.
- **Immediate Size Check**: Fails fast if the key is shorter than the data, avoiding hidden buffer quirks.

## Installation

1. Ensure you have Rust and Cargo installed.
2. Clone this repository and navigate to its directory:
   ```bash
   git clone https://github.com/yourusername/otp_streamer.git
   cd otp_streamer
   ```
3. Build the project:
   ```bash
   cargo build --release
   ```

## Usage

```bash
# Encrypt or decrypt (OTP is reversible by running again):
./target/release/otp_streamer <file-to-encrypt>
```

- Place your key in a file named `key.key` in the same directory.
- The tool will atomically overwrite `<file-to-encrypt>` with the encrypted/decrypted output.

## Why Chunked Streaming?

```
Yes—the chunked‐streaming version you’ve got is materially more reliable than that “all‑in‑memory” approach:

- **Predictable, bounded RAM**  
  • In‑memory: `fs::read` loads the *entire* input + key into RAM (twice, actually—once for each `Vec<u8>`), so you risk OOM or paging if either ever grows too big.  
  • Streaming: you only ever allocate two 64 KiB buffers, no matter how large your files get.

- **Immediate size check vs. hidden buffer quirks**  
  • In‑memory: you only discover a too‑small key when you try to index past its end (or crash).  
  • Streaming: you stat the file up front and fail immediately if the key is shorter, with a clear error.

- **Cleaner error recovery**  
  • In‑memory: if the write to disk fails midway, you’ve already got a 10 GiB `Vec` in scope and no way to roll back without extra code.  
  • Streaming: each chunk writes, flushes, and you only hold a small temp‑file handle—so failures happen in small, recoverable steps.

- **Cross‑platform atomicity**  
  • Both can do a temp‑file + rename, but streaming cleanly closes readers/writers before the rename on Windows.  
  • In‑memory has to drop the big buffers *and* file handles in the right order, which is easy to get wrong.

In practice, production‑grade tools almost always use chunked I/O for large files because it guarantees you’ll never blow out your memory or hit strange platform edge‑cases—exactly what you want when **reliability** is your #1 concern.
```

## License

MIT

