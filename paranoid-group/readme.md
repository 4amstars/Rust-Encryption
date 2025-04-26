# 🛡️ Paranoid Encryption Suite

**Paranoid** is a collection of standalone CLI encryption tools, each using a different modern and secure cryptographic algorithm. These tools are intentionally separated by algorithm, allowing users to:

- ✅ Use the cipher of their choice  
- 🔁 Chain multiple encryptions (double/triple encrypt)  
- 📦 Mix cipher types for paranoid-level security  
- 🧪 Experiment or compare performance and compatibility  

All tools support simple CLI usage in the form:

```
./<tool> E|D <filename> <password>
```

Where:  
- `E` = Encrypt  
- `D` = Decrypt  

All tools overwrite files **atomically**, using `.tmp` files and renaming for safety. All passwords are hashed with **Argon2**, and authenticated encryption is used when available.

---

## 🔐 Tools Overview

### 📁 `paes` – AES-256-GCM-SIV
- Uses **AES-256 in GCM-SIV mode** (nonce misuse resistant)
- Built with RustCrypto's `aes-gcm-siv` crate
- AEAD: ✅ Yes (encryption + authentication)
- Recommended for secure general-purpose use

---

### 📁 `pxch` – XChaCha20-Poly1305
- Uses **XChaCha20** stream cipher + Poly1305 MAC
- Built with `chacha20poly1305` crate (X variant)
- AEAD: ✅ Yes
- Excellent for speed, mobile, and large files

---

### 📁 `pser` – Serpent-256-EAX
- Uses **Serpent-256** (AES finalist) in **EAX** mode
- AEAD: ✅ Yes
- Great for those who prefer non-AES alternatives

---

### 📁 `pthr` – Threefish-1024 + HMAC
- Uses **Threefish-1024** (from Skein) with HMAC-SHA512
- Block size: 128 bytes, Key size: 1024 bits
- AEAD: ❌ (MAC is separate)
- Designed for ultra-paranoid archival encryption

---

### 📁 `pcam` – Camellia-256-EAX
- Uses **Camellia-256** in **EAX** mode
- AEAD: ✅ Yes
- Japan’s answer to AES; fast and secure

---

### 📁 `pkuz` – Kuznyechik (GOST R 34.12-2015) + EAX
- Uses **Kuznyechik**, the Russian national cipher
- AEAD: ✅ Yes (EAX)
- Ideal for compatibility with GOST-based systems

---

## 🔄 Combining Tools

You can encrypt a file multiple times with different tools for layered security:

```
./paes E secrets.txt mypassword
./pxch E secrets.txt myotherpassword
./pthr E secrets.txt ultraStrong!
```

> 🔁 To decrypt, reverse the order and use the correct passwords for each layer.

---

## 🔐 Default Behaviors

- All tools use **Argon2** for password-to-key derivation
- All outputs include salt, nonce (or tweak), and optionally HMAC tag
- Atomic file overwrite via `.tmp` + `rename`
- AEAD used when possible (EAX, GCM-SIV, Poly1305)

---

## 📁 Directory Structure

```
paranoid/
│
├── paes   → AES-256-GCM-SIV
├── pxch   → XChaCha20-Poly1305
├── pser   → Serpent-256-EAX
├── pthr   → Threefish-1024 + HMAC-SHA512
├── pcam   → Camellia-256-EAX
├── pkuz   → Kuznyechik + EAX
└── README.md
```

---

Made for those who like their crypto like their coffee:  
**paranoid and layered** ☕🛡️
