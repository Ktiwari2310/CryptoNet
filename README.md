# SecureText — Complete File Vault with Multi-Layer Protection & Tamper Defense

**SecureText** is a single-file Python 3 command-line security tool designed for Cryptography & Network Security (CNS) laboratory projects and demonstrations.

It provides complete file protection:
- **Confidentiality (Access Control)**: Only accessible with the correct password via Vernam stream cipher and PBKDF2-HMAC-SHA256 key stretching (100,000 rounds).
- **Anti-Rainbow Table Defense**: 16-byte cryptographically secure random salt (`os.urandom(16)`) per file.
- **Tamper Shield (Integrity & Authenticity)**: Keyed HMAC-SHA256 authentication tag + 128-bit MD5 checksum. Refuses to decrypt or leak any data if even 1 bit is altered.
- **Forensic Protection (Zero-Leakage)**: DoD 5220.22-M 3-pass secure shredding of plaintext and in-memory terminal viewing.

> [!NOTE]
> **Cryptographic Notice**: MD5 is used here for syllabus and demonstration purposes; in production SHA-256 or SHA-3 would be preferred since MD5 is vulnerable to collision attacks.

---

## File Structure

```
CryptoNet/
├── securetext.py       # Single-file CLI vault & tamper defense tool
├── sample.txt          # Sample document ready for testing
└── README.md           # Documentation, usage guide, and lab report notes
```

---

## Usage Guide

### 🌟 Quickest Presentation Demo (One-Click)
To demonstrate the complete lifecycle automatically in front of your teacher:
```bash
python securetext.py demo
```
*Walks through Locking $\rightarrow$ Viewing $\rightarrow$ Tampering $\rightarrow$ Tamper Defense rejection automatically.*

---

### Step-by-Step Commands

#### 1. Lock & Protect a File
Lock any file with your secret password:
```bash
python securetext.py lock sample.txt mypassword123
```
*Output: Creates `sample.txt.vault` containing the salt, HMAC authentication tag, MD5 checksum, and Vernam ciphertext.*

**Optional — Secure Shredding (`--shred`)**:
To securely wipe the original plaintext from the hard drive so it cannot be recovered by forensic recovery tools:
```bash
python securetext.py lock sample.txt mypassword123 --shred
```

---

#### 2. View File in Terminal (Zero Disk Footprint)
View the protected document in memory without writing unencrypted bytes to disk:
```bash
python securetext.py view sample.txt.vault mypassword123
```

---

#### 3. Unlock & Restore the File
Restore the original file with your password:
```bash
python securetext.py unlock sample.txt.vault mypassword123
```
*Output: Verifies HMAC authentication tag $\rightarrow$ Decrypts ciphertext $\rightarrow$ Verifies MD5 checksum $\rightarrow$ Restores `sample.txt`.*

---

#### 4. Test Wrong Password
```bash
python securetext.py unlock sample.txt.vault wrongpassword
```
*Output: `🚨 ACCESS DENIED: SECURITY SHIELD TRIGGERED!`*

---

#### 5. Simulate an Attacker Tampering with the File
Simulate an attacker modifying bytes in the protected vault:
```bash
python securetext.py tamper sample.txt.vault
```

Now try to unlock the file with the **correct** password:
```bash
python securetext.py unlock sample.txt.vault mypassword123
```
*Output*:
```text
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
🚨 ACCESS DENIED: SECURITY SHIELD TRIGGERED! 🚨
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
❌ EITHER:
   1. An INCORRECT password was entered.
   2. OR the file was MALICIOUSLY ALTERED/TAMPERED WITH in transit or storage!

🛡️ Defense Action: SecureText refuses to unlock or leak any data.
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
```

---

## Security Architecture & Mathematical Formulations

### 1. Key Derivation & Salt (PBKDF2-HMAC-SHA256)
- **16-byte Salt**: Ensures that encrypting the same file twice with the same password produces completely different vaults, rendering precomputed Rainbow Tables useless.
- **100,000 Rounds**: Artificially slows down brute-force and dictionary attacks.
- **Key Expansion**:
  $$\text{MasterKey} = \text{PBKDF2}(\text{password}, \text{salt}, 100000)$$
  $$\text{Keystream} = \text{SHA256}(\text{Key}_{enc} \parallel 0) \parallel \text{SHA256}(\text{Key}_{enc} \parallel 1) \dots$$

### 2. Vernam Stream Cipher (Bitwise XOR)
- Information-theoretic confusion:
  $$C_i = P_i \oplus K_i, \quad P_i = C_i \oplus K_i$$

### 3. Keyed HMAC-SHA256 Authentication Tag
- Protects against Man-in-the-Middle (MITM) ciphertext tampering:
  $$\text{AuthTag} = \text{HMAC-SHA256}(\text{Key}_{hmac}, \text{salt} \parallel \text{ciphertext})$$
- Even if an attacker intercepts the file, they cannot forge a valid HMAC tag without knowing the secret password.

### 4. Forensic Secure Shred (DoD 5220.22-M)
- Pass 1: Write all zeros (`0x00`)
- Pass 2: Write all ones (`0xFF`)
- Pass 3: Write cryptographically secure random bytes (`os.urandom`)
- Unlink file from filesystem.
