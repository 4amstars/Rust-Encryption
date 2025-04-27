# fs CLI



## 💡 Usage

```bash
# Encrypt a single file
fs encrypt <input_file> <output_file> -p "mySecretPassword"

# Decrypt it back
fs decrypt <output_file> <restored_file> -p "mySecretPassword"

# Encrypt or decrypt entire directories
fs encrypt ./my_data ./my_data.enc -p "password"
fs decrypt ./my_data.enc ./my_data.dec -p "password"
```

- `encrypt` / `decrypt`: operation mode
- `<input_path>`: file or directory to read
- `<output_path>`: file or directory to write
- `-p, --password`: the password used to derive the AES‑GCM key via PBKDF2

Passwords are never stored on disk; keys are derived in-memory with 100,000 PBKDF2 iterations.

---

## 🛠️ Under the Hood

- **Key Derivation**: PBKDF2 (HMAC‑SHA256, 100,000 iterations)
- **Auth‑Encrypted Cipher**: AES‑256‑GCM
- **Random Nonce**: 96‑bit per‑file nonce prepended to each ciphertext
- **Directory Traversal**: Recurses into subdirectories, preserving structure

All of the above logic is implemented in the `fs-encrypt` Rust crate; this binary simply wires the public API into a `main.rs` with argument parsing (via `clap`).

---


## 🤝 Contributing

Feel free to open issues or pull requests. Please follow the existing code style and include tests for any new behavior.

---

## 📜 License

This project is dual‑licensed under MIT OR Apache‑2.0. See [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE).

