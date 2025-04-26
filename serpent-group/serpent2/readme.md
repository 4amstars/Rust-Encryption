# Serpent 2

A secure file-encryption tool written in Rust using the Serpent block cipher (CBC mode) with HMAC-SHA256 authentication.

## Features

- **Argon2id** password-based key derivation (15 MiB memory, 3 iterations)
- **HKDF** to split the master key into separate encryption and authentication keys
- **Serpent (CBC)** encryption with PKCS#7 padding
- **HMAC-SHA256** encrypt-then-MAC authentication
- **Clap**-powered CLI with `encrypt`/`decrypt` subcommands
- **Secret zeroization** via `secrecy` and `zeroize` crates
- **Structured logging** with `env_logger`

## Requirements

- Rust toolchain (1.56 or newer)
- Internet connection to fetch dependencies

## Installation

```bash
# Clone the repo
git clone https://github.com/yourusername/serpent.git
cd serpent

# Build and install to your cargo bin path
cargo install --path .
```

## Usage

Encrypt a file (outputs `<input>.enc` by default):

```bash
serpent encrypt -i secret.txt
```

Decrypt a file (outputs `<input>.dec` by default):

```bash
serpent decrypt -i secret.txt.enc
```

You can also specify an output path:

```bash
serpent encrypt -i secret.txt -o encrypted.bin
serpent decrypt -i encrypted.bin -o decrypted.txt
```

## Logging

By default, only warnings and errors are printed. To enable info-level logging:

```bash
RUST_LOG=info serpent encrypt -i secret.txt
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/foo`)
3. Commit your changes (`git commit -m "Add foo feature"`)
4. Push to the branch (`git push origin feature/foo`)
5. Open a Pull Request

## License

This project is licensed under MIT. See [LICENSE](LICENSE) for details.

