# Text File Encrypter/Decrypter CLI Tool

A Python 3 command-line cryptography suite for the **Cryptography & Network Security (CNS)** laboratory project:
> **Syllabus Topic**: *"Create a command-line tool supporting custom key generation, Vernam (One-Time Pad) XOR operations, and Rail Fence transposition for text files."*

---

## Features

1. **Custom Key Generation (`keygen`)**:
   - Generates cryptographically secure, truly random One-Time Pad keys of arbitrary length using the OS CSPRNG (`secrets` module).
   - Alternatively supports deterministic password-derived keys via SHA-256 counter mode.
2. **Vernam (One-Time Pad) XOR Operations (`encrypt` / `decrypt`)**:
   - Implements Gilbert Vernam's cipher (1917) providing information-theoretic confusion ($C_i = P_i \oplus K_i$).
3. **Rail Fence Transposition**:
   - Positional diffusion layer applied after the Vernam cipher with configurable rails (default 3 rails).
4. **Cryptographic Integrity & Tamper Detection**:
   - 128-bit MD5 checksum computed on the original plaintext and verified during decryption.
5. **Cryptanalysis & Frequency Analysis (`analyze`)**:
   - Computes Shannon Entropy (0 to 8 bits/byte) and displays ASCII character frequency histograms to show how encryption eliminates statistical patterns.
6. **One-Click Automated Presentation Demo (`demo`)**:
   - Executes all features in sequence for teacher/examiner evaluations.

---

## File Structure

```
CryptoNet/
├── filecipher.py       # Main command-line tool
├── sample.txt          # Sample text file ready for testing
└── README.md           # Documentation, usage guide, and lab report notes
```

---

## Quick Start (Git Bash / PowerShell)

Navigate to the project directory:
```bash
cd /c/Users/KHUSHBOO/.gemini/antigravity/scratch/CryptoNet
```

### 🌟 1-Click Lab Presentation Demo (Recommended for Teacher)
Run the automated end-to-end presentation:
```bash
python filecipher.py demo
```

---

### Step-by-Step Commands

#### 1. Generate a Custom One-Time Pad Key
Generate a 100-byte random keyfile:
```bash
python filecipher.py keygen 100 -o mykey.key
```

#### 2. Analyze Plaintext Before Encryption
View character frequencies and Shannon entropy of the plaintext:
```bash
python filecipher.py analyze sample.txt
```

#### 3. Encrypt a Text File (Vernam XOR + Rail Fence)
Encrypt using your custom keyfile:
```bash
python filecipher.py encrypt sample.txt --key mykey.key --rails 3
```
*(You can also use a password string instead of a keyfile: `--key mypassword`)*.
- Generates `sample.txt.enc` and `sample.txt.hash`.

#### 4. Analyze Ciphertext After Encryption
See how encryption destroyed letter frequencies:
```bash
python filecipher.py analyze sample.txt.enc
```
*(Notice the entropy approaches 8.0 bits/byte and frequency histogram flattens).*

#### 5. Decrypt the Text File
```bash
python filecipher.py decrypt sample.txt.enc --key mykey.key --rails 3
```
- Output:
  `✅ VERIFIED — FILE IS UNTAMPERED & AUTHENTIC!`
  Creates `sample.txt.decrypted`.

#### 6. Simulate Tamper Attack
Simulate an attacker altering bytes in transit:
```bash
python filecipher.py tamper sample.txt.enc
```
Now attempt decryption:
```bash
python filecipher.py decrypt sample.txt.enc --key mykey.key --rails 3
```
- Output:
  `⚠️ WARNING — TAMPERING OR WRONG KEY DETECTED!`

---

## Theoretical Foundations for Lab Reports

### 1. Confusion and Diffusion (Claude Shannon)
- **Confusion (Vernam XOR)**: Obscures the relationship between the plaintext and ciphertext by bitwise XORing each byte with a key byte ($C_i = P_i \oplus K_i$).
- **Diffusion (Rail Fence)**: Distributes the statistical structure of the plaintext across the ciphertext by rearranging byte positions along zigzag rails.

### 2. Shannon Entropy
Measures randomness on a scale of 0 to 8 bits/byte:
$$H = -\sum_{i=0}^{255} p(x_i) \log_2 p(x_i)$$
- Natural English text has an entropy of ~4.0 - 5.0 bits/byte due to language redundancy.
- Hybrid Vernam + Rail Fence ciphertext approaches 7.9 - 8.0 bits/byte.
