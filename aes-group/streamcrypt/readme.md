# 🔐 streamcrypt v2

**streamcrypt** is a Rust-based file encryption tool with **two modes**: password-only `--nokey` mode and passphrase-wrapped keyset mode.

It uses modern, secure cryptography (Argon2id + AES-GCM) and outputs a **self-contained encrypted format** that includes all required metadata. Tamper detection is built-in — if any byte changes, decryption fails.

## ⚙️ How it works

- **Password-only mode** (`--nokey`): uses Argon2id to derive a key from your password and AES-GCM to encrypt/decrypt. *This mode buffers the entire file in memory (not streaming).*  
- **Keyset mode**: wraps a Tink keyset with a passphrase (PBKDF2-HMAC-SHA256) and then uses Tink's streaming‑AEAD for true streaming encryption/decryption.

## 📦 SCRY File Format (in --nokey mode)

```text
[ MAGIC   ][ VER ][ SALT (16) ][ NONCE (12) ][ CIPHERTEXT... ]
[ b"SCRY" ][ 0x01 ][ random    ][ random     ][ AES-GCM output ]
```

This format is self-validating and secure by design.

## 🚀 Usage

### 🔐 Encrypt with password-only

```bash
streamcrypt --nokey encrypt file.txt file.scry
```

You’ll be prompted to enter and confirm a password.  
*Note: encryption buffers the whole file in memory.*

### 🔓 Decrypt

```bash
streamcrypt --nokey decrypt file.scry file.txt
```

Enter the same password you used to encrypt.

> **Note:** The password is never stored, and each encryption uses a new salt + nonce. Even with the same password, every encrypted file will be unique.

### 🔐 Keyset mode (advanced users)

```bash
# Generate a new keyset wrapped with a passphrase
streamcrypt --passphrase hunter2 keygen

# Encrypt using the saved keyset
streamcrypt --passphrase hunter2 encrypt file.txt file.enc

# Decrypt
streamcrypt --passphrase hunter2 decrypt file.enc file.txt
```

## 🛡️ Security Model

- Every file is authenticated with AES-GCM — if any bit is changed, decryption fails.  
- Argon2id is used for password hardening (slow brute-force resistance).  
- No AAD is required or accepted — this reduces the chance of mismatches or errors.  
- The file format is binary and deterministic — safe for archiving, transport, or nesting.

## ✅ Features

- Modern cryptography (AES-GCM + Argon2id)  
- Self-contained file format (SCRY1)  
- No AAD required  
- Keyset wrapping (Tink compatible)  
- Streaming encryption in keyset mode  
- CLI-friendly, secure by default  
- Zero third-party servers — fully local

## 🧪 Future Ideas

- `--inspect` command to show file headers  
- `--base64` mode for printable output  
- Public key hybrid encryption  
- Encrypted metadata blocks

---

*Built with ❤️ in Rust · Encrypted like a Samurai 🥷*

