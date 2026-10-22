# SecureText — Encrypted File Vault with Integrity Verification

A single-file Python 3 command-line security tool demonstrating fundamental **Cryptography & Network Security (CNS)** concepts:
1. **Confidentiality**: Vernam Cipher (One-Time Pad style stream cipher using bitwise XOR).
2. **Key Derivation**: Pseudo-random keystream expansion using SHA-256 in counter mode.
3. **Integrity Auditing**: Cryptographic verification using 128-bit MD5 hashing.
4. **Attack Simulation**: Simulated Man-in-the-Middle (MITM) bit-flipping attack to verify tamper detection.

> [!NOTE]
> **Cryptographic Notice**: MD5 is used here for syllabus and academic demonstration purposes. In production systems, modern secure hash functions such as **SHA-256** or **SHA-3** must be preferred because MD5 is cryptographically broken against collision attacks.

---

## Requirements

- **Python 3.6+** (Standard Library only)
- **Zero external dependencies** (no `pip install` required!)

---

## File Structure

```
CryptoNet/
├── securetext.py       # Single-file CLI encryption & integrity tool
├── sample.txt          # Sample text file ready for demonstration
└── README.md           # Documentation and lab viva guide
```

---

## How to Run & Usage Examples

### 1. Encrypt a File
Encrypt any file using a custom password:
```bash
python securetext.py encrypt sample.txt mysecretpassword
```
**What happens**:
- Computes the MD5 integrity hash of the original plaintext.
- Derives a keystream of identical byte length from `mysecretpassword` using SHA-256 counter mode.
- Encrypts file bytes using Vernam bitwise XOR ($C[i] = P[i] \oplus K[i]$).
- Creates two output files:
  - `sample.txt.enc`: Encrypted ciphertext bytes.
  - `sample.txt.hash`: Text file containing original MD5 hash.
- Logs encryption time in milliseconds.

---

### 2. Decrypt a File (Normal Case - Untampered)
Decrypt the file using the original password:
```bash
python securetext.py decrypt sample.txt.enc mysecretpassword
```
**Output**:
```text
✅ Verified — file is untampered
   The file decrypted perfectly and matches the original cryptographic hash.
```
- Recreates the plaintext at `sample.txt.decrypted`.
- Confirms the computed MD5 of the decrypted file matches the stored reference hash.

---

### 3. Decrypt with Wrong Password
Attempt to decrypt using an incorrect password:
```bash
python securetext.py decrypt sample.txt.enc wrongpassword
```
**Output**:
```text
⚠️ WARNING — file has been modified or wrong password used
   Integrity verification failed! The decrypted content does NOT match the original.
```
- Because XOR with a wrong keystream yields scrambled gibberish, the recomputed MD5 hash diverges completely, immediately alerting the user.

---

### 4. Tamper Attack Simulation (Lab Viva Demo)
Simulate an attacker intercepting the ciphertext and flipping random bits:
```bash
python securetext.py tamper sample.txt.enc
```
**Output**:
```text
⚠️ SECURETEXT — SIMULATED FILE TAMPER ATTACK
[*] Modifying 3 byte(s) at random offsets to simulate tampering:
    - Offset  14: 0x4a -> 0xb5 (Bitwise Inverted)
    - Offset  88: 0x1f -> 0xe0 (Bitwise Inverted)
    - Offset 122: 0x9c -> 0x63 (Bitwise Inverted)
⚠️ TAMPER COMPLETE! 'sample.txt.enc' has been maliciously altered.
```

Now re-run decryption with the correct password:
```bash
python securetext.py decrypt sample.txt.enc mysecretpassword
```
**Output**:
```text
⚠️ WARNING — file has been modified or wrong password used
   Integrity verification failed! The decrypted content does NOT match the original.
```
This visually demonstrates the fundamental principle of **Cryptographic Integrity**: any alteration in the encrypted ciphertext is immediately flagged.

---

## Mathematical Foundations for Lab Reports

### 1. Vernam Cipher (Bitwise XOR)
Invented by Gilbert Vernam in 1917. Operating on individual bytes:
$$\text{Encryption: } C_i = P_i \oplus K_i$$
$$\text{Decryption: } P_i = C_i \oplus K_i$$

Because bitwise XOR is self-inverse:
$$(P_i \oplus K_i) \oplus K_i = P_i \oplus (K_i \oplus K_i) = P_i \oplus 0 = P_i$$

### 2. SHA-256 Counter-Mode Keystream Derivation
To prevent simple repeating key vulnerabilities (Vigenère-style periodic attacks), the password seeds an incrementing 32-bit counter hashed with SHA-256:
$$\text{Keystream} = \text{SHA256}(P \parallel 0) \parallel \text{SHA256}(P \parallel 1) \parallel \dots$$
Truncated to exactly the required file length $L$.

### 3. MD5 Integrity Hashing
Produces a 128-bit digest of the original file. Even a single bit change in plaintext alters roughly 50% of the hash output bits due to the **avalanche effect**, making tampering detection instantaneous.
