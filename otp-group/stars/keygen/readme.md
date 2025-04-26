# dkey: Deterministic Cryptographic Key Generator

**dkey** is a command-line tool for generating deterministic, high-entropy key files of arbitrary size from a single password. It combines a memory-hard KDF (Argon2id) with a cryptographically secure stream generator (BLAKE3 XOF or ChaCha20) to produce pseudorandom bytes that look indistinguishable from random data, yet are fully reproducible given the same inputs.

---

## Table of Contents

1. [How It Works](#how-it-works)
2. [Features](#features)
3. [Installation](#installation)
4. [Basic Usage](#basic-usage)
5. [Enhanced CLI Options](#enhanced-cli-options)
6. [Security Considerations](#security-considerations)
7. [License](#license)

---

## How It Works

1. **Password-Based Key Derivation (Argon2id)**
   - Argon2id is a memory- and CPU-hard function designed to resist both GPU and ASIC attacks.
   - We derive a 32‑byte seed by hashing your password (plus a static or provided salt) with Argon2id.
   - You can adjust Argon2 parameters to tune memory usage (`--argon2-memory`), time cost (`--argon2-time`), and parallelism (`--argon2-par`).

2. **Seed to Pseudorandom Stream**
   - The 32‑byte seed is then fed into one of two secure stream generators:
     - **BLAKE3 XOF (default)**: an extendable-output function that expands the seed into as many bytes as you like, with cryptographic strength.
     - **ChaCha20 stream cipher (optional)**: a fast, nonce-based stream cipher repurposed here for deterministic output (by seeding with our fixed seed).

3. **File Output**
   - The chosen generator writes pseudorandom data in buffered chunks to your output file.
   - The final key file is reproducible anytime you run the same command with the same password and parameters.

---

## Features

- **Deterministic**: Re-run with the same inputs to get the same key file.
- **Memory-hard**: Argon2id defends against brute-force with configurable memory and time costs.
- **Flexible output**: Choose BLAKE3 XOF or ChaCha20 generator.
- **Custom salt**: Override the compile-time salt for a different key "universe." Use `--salt` with a base64 string.
- **Zeroize**: Password and seed memory cleared after use to reduce residual data leaks.
- **CLI-driven**: Built with `clap` for intuitive option parsing.

---

## Installation

1. Ensure you have Rust (edition 2024) installed:  
   ```sh
   rustup install stable
   rustup default stable
   ```
2. Clone and build:
   ```sh
   git clone https://github.com/your-repo/dkey.git
   cd dkey
   cargo build --release
   ```
3. Copy the binary to your PATH:
   ```sh
   cp target/release/dkey /usr/local/bin/
   ```

---

## Basic Usage

Generate a 10 MiB key file with default settings:
```sh
dkey 10mb
```  
Outputs `key.key` in the current directory.

---

## Enhanced CLI Options

| Flag                         | Description                                                                                  | Example                                                                                 |
|------------------------------|----------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------|
| `-o, --output <path>`        | Set the output file name/path (default: `key.key`).                                          | `dkey -o secret.bin 50mb`                                                               |
| `-s, --salt <base64>`        | Override compile-time salt (raw base64).                                                    | `dkey --salt Q2hhbmdlU2FsdA== 1mb`                                                       |
| `-a, --algo <blake3|chacha>` | Choose generator: BLAKE3 XOF (default) or ChaCha20 stream.                                   | `dkey -a chacha 100kb`                                                                   |
| `--argon2-memory <KiB>`      | Argon2 memory cost in KiB (default: 524288 = 512 MiB).                                       | `dkey --argon2-memory 262144 5mb`                                                        |
| `--argon2-time <iterations>` | Argon2 time cost (passes over memory) (default: 10).                                         | `dkey --argon2-time 20 5mb`                                                              |
| `--argon2-par <threads>`     | Argon2 parallelism (threads) (default: 1).                                                   | `dkey --argon2-par 2 5mb`                                                                |


**Examples**:

- Generate 100 MiB with ChaCha20 and faster KDF:
  ```sh
  dkey -a chacha --argon2-time 5 100mb
  ```

- Generate 50 MiB to `secret.bin` with custom salt:
  ```sh
  dkey -o secret.bin --salt QW5vdGhlclNhbHRTdHJpbmc= 50mb
  ```

---

## Security Considerations

- **Salt stability**: The compile-time salt ensures consistency across runs. Changing it (via `--salt`) creates a new key space.
- **Parameter tuning**: Higher memory/time increases resistance to brute-force but increases CPU/memory usage.
- **Determinism**: If someone knows your password, they can reproduce your key. Keep passwords and salts secret.
- **Zeroization**: Sensitive data is wiped from memory where possible, but cannot guarantee at OS level.

---

## License

This project is licensed under the [MIT License](LICENSE).

