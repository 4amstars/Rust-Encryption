# aead_stream_app

A simple command‑line tool for chunked AEAD encryption and decryption of files, built on Google Tink’s streaming‑AEAD API.

---

## 📚 Overview

`aead_stream_app` leverages Tink’s battle‑tested Streaming AEAD primitive to encrypt and decrypt arbitrarily large files in fixed‑size chunks. By streaming data rather than buffering entire files in memory, it supports files of any size with minimal footprint.

This CLI is intended as a reference/demo scaffold—you’ll find it easy to integrate into larger pipelines, wrap keysets with secure key‑encrypting keys, and add production‑grade features (logging, testing, deployment).

---

## ✨ Features

- **Streaming AEAD**: Encrypt/decrypt data in 4 KB chunks using AES‑GCM‑HKDF.
- **Small memory footprint**: No need to load entire files into RAM.
- **Clear CLI**: Two subcommands (`encrypt` and `decrypt`) with simple positional arguments.
- **Cross‑platform**: Written in Rust, runnable wherever you can install a Rust tool.

---

## 🛠️ Requirements

- **Rust** ≥ 1.72 (2024 edition)
- **Dependencies** as specified in `Cargo.toml`:
  - `tink-core 0.3.0` (with `insecure` feature)
  - `tink-streaming-aead 0.3.0`
  - `clap 4.5.37` (derive feature)
  - `rand 0.9.1`
  - `anyhow 1.0.98`

---

## 🚀 Installation

```bash
# Clone the repo
git clone https://github.com/your-org/aead_stream_app.git
cd aead_stream_app

# Build the CLI
cargo install --path .
```

The `aead_stream_app` binary will be placed in your Cargo bin directory (e.g. `~/.cargo/bin`).

---

## 📖 Usage

All commands follow the pattern:

```bash
aead_stream_app <COMMAND> <INPUT_FILE> <OUTPUT_FILE> <KEY_FILE>
```

### 1. Encrypt

```bash
aead_stream_app encrypt plaintext.txt ciphertext.bin keyset.json
```

- **plaintext.txt**: Path to your cleartext file.
- **ciphertext.bin**: Path to write the encrypted output.
- **keyset.json**: Path to write the (insecure) cleartext keyset.

On success, you’ll get your encrypted data in `ciphertext.bin` and the raw keyset in `keyset.json`.

### 2. Decrypt

```bash
aead_stream_app decrypt ciphertext.bin recovered.txt keyset.json
```

- **ciphertext.bin**: Encrypted input file.
- **recovered.txt**: Path to write the decrypted output.
- **keyset.json**: Path to read the cleartext keyset.

This will reverse the streaming AEAD process and restore the original contents.

---

## 🔑 Key Management & Security

By default, this tool writes your Tink keyset **unencrypted**—the same as putting a private key on disk in the clear. This is fine for experimentation, but **never** leave secret key material exposed in production.

### Wrapping your keyset

Use Tink’s `EncryptedWriter`/`EncryptedReader` (or a passphrase/KMS‑backed AEAD) to protect your keyset at rest:

```rust
use tink_core::keyset::{EncryptedWriter, EncryptedReader};
use tink_aead::subtle::Aes256Gcm;  // or your KMS AEAD

// Derive or load a key‑encrypting key (KEK)...
let kek = Aes256Gcm::new(&master_key_bytes);

// Writing encrypted keyset:
let mut fw = File::create("encrypted_keyset.bin")?;
let mut ew = EncryptedWriter::new(Box::new(fw), &kek);
write_keyset(&handle, &mut ew)?;
ew.close()?;
```

Refer to Google Tink’s docs for full details on secure key wrapping.

---

## 🧪 Testing & CI

- **Unit tests**: Add tests for encrypt/decrypt round‑trips, error conditions, and edge cases.
- **Integration**: Automate tests on large files and networks (simulate partial reads/writes).
- **CI/CD**: Use GitHub Actions or another pipeline to build, test, and release versions.

---

## 📦 Packaging & Distribution

- **crates.io**: Publish your CLI as a Rust crate.
- **Platform packages** (Debian, Homebrew, etc.): Create native packages for end users.
- **Docker**: Provide a container image for users without Rust.

---

## 🤝 Contributing

1. Fork the repo
2. Create a feature branch
3. Submit a PR with tests and documentation

Please follow the Coding Style & Contribution Guidelines in `CONTRIBUTING.md`.

---

## 📝 License

[Apache‑2.0](https://www.apache.org/licenses/LICENSE-2.0) © Your Name or Organization

---

*Built with ❤️ and Google Tink.*

