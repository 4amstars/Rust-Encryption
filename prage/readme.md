# 🔐 Prage - Minimal Age-Compatible File Encryption with a Password

**Prage** (short for **Password Rage**) is a streamlined Rust CLI tool that performs secure file encryption and decryption using a passphrase — fully compatible with the `rage` tool and [age-encryption.org/v1](https://age-encryption.org/v1) format.

Inspired by [`rage`](https://github.com/str4d/rage), but focused solely on the password-based encryption path, **Prage** is ideal for learners and those who want an ultra-minimal standalone binary for secure file encryption using just a password.

---

## ✨ Why Prage?

- ✅ Based on the same encryption logic as `rage`, using `age::Encryptor::with_user_passphrase`.
- ✅ Built in pure Rust with strong memory safety and zero unsafe code.
- ✅ Streams input in chunks, making it suitable for large files.
- ✅ Tiny and portable.
- ✅ Great for learning how age-based encryption works without needing full rage complexity.

---

## 🔧 Usage

```bash
# Encrypt a file with a password
prage enc input.txt encrypted.age

# Decrypt the file (prompts for same password)
prage dec encrypted.age output.txt
```

The encrypted format is fully interoperable with `rage`.

All operations are interactive — the app prompts for a password securely using hidden input.

---

## 🔐 How Secure Is It?

Prage uses:

- `age` crate's built-in `scrypt` password-based encryption.
- AES-based payload encryption via the age format.
- Authenticated encryption with integrity checks.
- Password-based key derivation via scrypt (with automatic memory-hard work factor tuning).
- Chunked I/O for low-memory use and performance.

You are using the same encryption flow that `rage` uses internally, just with a narrowed scope.

---

## 📦 Installation

1. Clone or download this repo.
2. Build with Rust:

```bash
cargo build --release
```

The resulting binary is in `target/release/prage`.

---

## 📚 Learning Purposes

Prage is a great learning project to see how real-world file encryption works using:

- Password-based key derivation (PBKDF).
- Streaming authenticated encryption.
- Handling binary file formats with magic headers and nonces.
- Clean separation of logic into simple CLI inputs.

If you're a beginner learning Rust and cryptography, this tool was made with you in mind ❤️

---

## 🧾 Credits and Licensing

- 🔧 **Written by:** Rust Samurai – an AI assistant powered by OpenAI.
- 🧠 **Inspired by:** [`rage`](https://github.com/str4d/rage) by Filippo Valsorda and contributors.
- 🧪 **Encryption engine:** Uses the `age` crate directly.
- 📜 **License:** Dual-licensed under either:
  - MIT ([LICENSE-MIT](LICENSE-MIT))
  - Apache 2.0 ([LICENSE-APACHE](LICENSE-APACHE))

You may choose either license. See the `LICENSE-*` files for details.

---

## ❤️ Contributions

This project was created by AI with a passion for teaching and strong encryption. If you enjoy it, feel free to share, adapt, or build on it!

---
