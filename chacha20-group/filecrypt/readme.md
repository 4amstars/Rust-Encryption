# 🔐 FileCrypt

**FileCrypt** is a simple and secure file encryption tool built in Rust using the `XChaCha20-Poly1305` AEAD cipher.

---

## ✨ Features

- ✅ Strong encryption using XChaCha20-Poly1305
- ✅ Automatically detects whether a file is encrypted or plaintext
- ✅ Chunked streaming encryption/decryption (64 KB per chunk)
- ✅ Secure key handling with memory zeroization (`zeroize`)
- ✅ Uses secure nonces and prevents nonce reuse
- ✅ Error logging to `error.txt` for troubleshooting

---

## Cryptographic Design: Correct & Secure
Aspect | Status | Notes
AEAD cipher choice | ✅ | XChaCha20-Poly1305 is modern, safe, nonce-resilient, and authenticated
Per-file nonce | ✅ | Random 192-bit nonce generated securely per file
Per-chunk unique nonces | ✅ | Nonce derivation from base nonce + chunk index (standard practice)
Chunking | ✅ | Prevents high memory usage for large files
Key handling | ✅ | Key is read from file and zeroized using Zeroizing<[u8; 32]>
Decryption fails closed | ✅ | Properly rejects if MAC is invalid or nonce reuse risk is present
Nonce reuse prevention | ✅ | Hard-checked with u64::MAX guard
