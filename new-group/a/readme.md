# 🔐 a — Minimal, Production-Safe File Encryption CLI

`a` is a minimal command-line tool built in Rust for encrypting and decrypting files using the [age](https://github.com/FiloSottile/age) encryption format.

This app is:

- ✅ Safe (uses no unsafe or cryptographic primitives directly)
- ✅ Compatible with [`rage`](https://github.com/str4d/rage)
- ✅ Built on top of the audited [`age`](https://crates.io/crates/age) crate
- ✅ Supports streamed encryption/decryption for large files
- ✅ Cross-platform and fast

---

## 🛠 Installation

Make sure you have Rust installed:  
https://rustup.rs

```bash
git clone https://github.com/your-user/a.git
cd a
cargo build --release
```

Binary will be available at: `target/release/a`

---

## 🔑 Key Format

This CLI uses age-compatible X25519 key pairs.  
Keys are expected in the `rage` format:

Generated via:

```bash
rage-keygen -o my.key
```

Contents of a valid key:

```
# created: 2025-04-24T17:35:00-04:00
# public key: age1...
AGE-SECRET-KEY-1....
```

---

## 🧪 Quick Start (with Default Key)

This tool supports generating a fixed default key for testing/demo purposes:

```bash
a generate-default-key
```

This creates `shinobi-test.key` and outputs a fixed public key:

```text
Public: age1s9jsd0uju4f482h73menxuwggezyedw3yf29hk3dlxnguevnhuqqmjs837
```

### Encrypt with the Default Key

```bash
a encrypt -i a.txt -o b.txt -r age1s9jsd0uju4f482h73menxuwggezyedw3yf29hk3dlxnguevnhuqqmjs837
```

### Decrypt with the Default Key File

```bash
a decrypt -i b.txt -o c.txt -k shinobi-test.key
```

---

## 📦 Commands

### `a encrypt`

Encrypts a file using an `age` recipient key.

#### Flags:
| Flag | Description |
|------|-------------|
| `-i`, `--input` | Path to the plaintext file |
| `-o`, `--output` | Path to the encrypted output file |
| `-r`, `--recipient` | `age1...` public key from keygen |

---

### `a decrypt`

Decrypts a file using a secret identity key (private key).

#### Flags:
| Flag | Description |
|------|-------------|
| `-i`, `--input` | Path to the encrypted file |
| `-o`, `--output` | Output file (plaintext) |
| `-k`, `--key` | Path to a key file created with `rage-keygen` |

---

### `a generate-default-key`

Writes a hardcoded test keypair to `shinobi-test.key`  
⚠️ Not secure — only for local testing/demo.

---

## 🛡 Security Notice

This tool is built on **age 0.11.1**, using only safe and audited cryptographic abstractions.  
No cryptography is implemented manually.  
It is suitable for real use **when used with keys created via `rage-keygen`**.

Do **not** use the default key mode for anything sensitive. It's for testing only.

---

## 📚 Compatibility

This CLI is compatible with:

- Files encrypted using `rage`
- Files decrypted using this tool + `rage`-style private keys
- Linux, Windows, macOS

---

## ✅ License

MIT or Apache 2.0 — your choice.

---

## 🙏 Credits

- [age](https://github.com/FiloSottile/age) by @FiloSottile  
- [rage](https://github.com/str4d/rage) by @str4d  
- Rust community 💛

---
