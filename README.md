# CryptoNet — Secure Chat with Built-In Network Security Audit

**CryptoNet** is a Python 3 client-server secure chat system designed for Cryptography and Network Security (CNS) laboratory experiments and demonstrations. It combines classical substitution/transposition ciphers with modern public-key cryptography, digital signatures, and cryptographic integrity verification.

---

## Architecture Overview

```
                                [ CLIENT ]                                              [ SERVER ]
                                    |                                                       |
   1. TCP Handshake                 |================== TCP Port 9999 =====================>|
                                    |                                                       |
   2. Diffie-Hellman Handshake     |<----------------- Server DH Pub Key (B) + RSA Pub -----|
      & RSA Public Key Exchange     |------ Client DH Pub Key (A) + RSA Pub --------------->|
                                    |                                                       |
      Independent Secret Derivation | [Compute s = B^a mod p]             [Compute s = A^b mod p]
                                    |  Verify s_client == s_server (RFC 3526 2048-bit MODP) |
                                    |  Derive Session Key = SHA256(s)                       |
                                    |                                                       |
   3. Outgoing Message Pipeline:    |                                                       |
      [Plaintext Input]             |                                                       |
             |                      |                                                       |
      [MD5 Hash & Timing Log]       |                                                       |
             |                      |                                                       |
      [Primary Cipher]              |                                                       |
      (Vernam OTP / Hill / Caesar)  |                                                       |
             |                      |                                                       |
      [Transposition Layer]         |                                                       |
      (Rail Fence Cipher)           |                                                       |
             |                      |                                                       |
      [RSA-2048 Digital Signature]  |                                                       |
      (PKCS#1 v1.5 with SHA-256)    |                                                       |
             |                      |                                                       |
   4. Wire Transmission (JSON)      |==================== Wire Payload ====================>|
                                    |                                                       |
                                    |                                 5. Incoming Pipeline: |
                                    |                                    [Verify RSA Sig]   |
                                    |                                    [Invert Rail Fence]|
                                    |                                    [Decrypt Primary]  |
                                    |                                    [Verify MD5 Hash]  |
                                    |                                    [Display Message]  |
```

---

## Project Structure

```
CryptoNet/
├── crypto_utils.py       # All cipher implementations (DH, Caesar, Vernam, Hill, Rail Fence, RSA, MD5)
├── server.py             # TCP socket server with interactive chat loop & CLI pipeline inspection
├── client.py             # TCP socket client with interactive chat loop & CLI pipeline inspection
├── test_integration.py   # Automated unit and integration test suite
├── logs/                 # Captured benchmarks and hash timing metrics
│   └── hash_timing.log   # Tabulated MD5 generation time and throughput across message sizes
└── README.md             # Setup guide, run instructions, and network security audit manual
```

---

## Requirements & Prerequisites

- **Python**: Python 3.8+ (Tested on Python 3.10, 3.11, 3.12, 3.13)
- **Dependencies**: Only `pycryptodome` (pure Python standard library for everything else)

### Installation

```bash
pip install pycryptodome
```

---

## How to Run

### 1. Baseline Plaintext Mode (Unencrypted Comparison)

Runs raw, unencrypted TCP socket messaging. Designed specifically for Wireshark packet capture comparison against the encrypted pipeline.

**Terminal 1 (Server):**
```bash
python server.py --plain
```

**Terminal 2 (Client):**
```bash
python client.py --plain
```

### 2. Encrypted Mode (Default: Vernam OTP + Rail Fence)

Executes Diffie-Hellman 2048-bit key exchange, RSA-2048 signature generation, Vernam OTP encryption, Rail Fence transposition (depth 3), and MD5 integrity verification.

**Terminal 1 (Server):**
```bash
python server.py
```

**Terminal 2 (Client):**
```bash
python client.py
```

### 3. Switching Ciphers via Command-Line Flags

You can specify the primary cipher and Rail Fence depth when starting either client or server:

- **Vernam Cipher (Default)**:
  ```bash
  python server.py --cipher vernam --rails 3
  python client.py --cipher vernam --rails 3
  ```
- **Hill Cipher (2x2 Matrix Modulo 256)**:
  ```bash
  python server.py --cipher hill --rails 3
  python client.py --cipher hill --rails 3
  ```
- **Caesar Cipher (Weak Demonstration Cipher)**:
  ```bash
  python server.py --cipher caesar --rails 3
  python client.py --cipher caesar --rails 3
  ```

### 4. Interactive Runtime Commands

During an active chat session, both client and server support in-chat commands:

| Command | Description |
| :--- | :--- |
| `/cipher <vernam\|hill\|caesar>` | Dynamically switch primary encryption cipher |
| `/rails <int>` | Set Rail Fence transposition depth (e.g., `/rails 4`) |
| `/tamper` | Toggle simulated Man-in-the-Middle (MITM) bit-flip on next outgoing payload |
| `/bench` | Execute automated MD5 timing benchmarks and write to `logs/hash_timing.log` |
| `/plain` | Toggle between plaintext baseline mode and encrypted mode |
| `/help` | Display command help menu |
| `/quit` | Cleanly terminate session and close sockets |

---

## Cryptographic Components Detail

### 1. Diffie-Hellman Key Exchange
- Uses **RFC 3526 2048-bit MODP Group 14** ($g = 2$).
- Server generates private key $b$, sends $B = g^b \pmod p$.
- Client generates private key $a$, sends $A = g^a \pmod p$.
- Both independently calculate:
  $$s = B^a \pmod p = A^b \pmod p = g^{ab} \pmod p$$
- Both print the shared secret on the console to prove mathematical agreement without transmitting the secret over the wire.
- 256-bit symmetric session key is derived using $\text{SHA-256}(s)$.

### 2. Primary Ciphers (Interchangeable)
- **Vernam Cipher (One-Time Pad style)**:
  Generates a cryptographically strong pseudorandom keystream using SHA-256 in counter mode keyed from the DH session key. Applies bitwise XOR:
  $$C_i = P_i \oplus K_i, \quad P_i = C_i \oplus K_i$$
- **Hill Cipher**:
  Implemented over $\mathbb{Z}_{256}$ (full byte space) using a $2 \times 2$ matrix $K$ derived deterministically from the DH session key. The determinant $\det(K)$ is guaranteed to be odd ($\gcd(\det, 256) = 1$). Inversion is computed via modular inverse:
  $$\vec{c} = K \cdot \vec{p} \pmod{256}, \quad \vec{p} = K^{-1} \cdot \vec{c} \pmod{256}$$
- **Caesar Cipher**:
  Classical monoalphabetic shift cipher ($C_i = (P_i + k) \pmod{256}$) provided as a baseline to demonstrate vulnerability to frequency analysis.

### 3. Transposition Layer (Rail Fence)
- Ciphertext output from the primary cipher is passed through an $N$-rail zigzag transposition cipher before socket transmission.
- Receiver reverses the zigzag transposition pattern before performing primary decryption.

### 4. Authentication & Non-Repudiation (RSA-2048)
- Each peer generates a 2048-bit RSA key pair (`Crypto.PublicKey.RSA`).
- Public keys (PEM format) are exchanged during the initial handshake.
- Every outgoing message is signed using **PKCS#1 v1.5** over the SHA-256 digest of the ciphertext.
- Receiver verifies the signature before processing; invalid signatures immediately trigger an authentication alarm.

### 5. Integrity Auditing (MD5 Hashing & Benchmarks)
- Sender computes $\text{MD5}(\text{plaintext})$ and transmits the 128-bit hash alongside the envelope.
- Receiver decrypts the ciphertext, recomputes $\text{MD5}(\text{decrypted\_plaintext})$, and compares them.
- High-precision execution timing is recorded using `time.perf_counter_ns()` and logged to `logs/hash_timing.log`.

---

## Network Security Audit & Lab Testing Guide

This section outlines how external security tools integrate with running CryptoNet instances for laboratory demonstrations and reports.

### A. Wireshark (Packet Sniffing & Traffic Analysis)

#### Objective
Compare packet contents between baseline plaintext mode (`--plain`) and encrypted mode (`--cipher vernam`).

#### Step-by-Step Procedure
1. Launch Wireshark and select your capture interface (`Adapter for loopback traffic capture` on Windows or `lo` on Linux).
2. Set display filter:
   ```text
   tcp.port == 9999
   ```
3. **Capture Plaintext Session**:
   - Start `python server.py --plain` and `python client.py --plain`.
   - Send: `"Meet me at the secret rendezvous point."`
   - In Wireshark, right-click any captured TCP segment $\rightarrow$ **Follow** $\rightarrow$ **TCP Stream**.
   - **Observation**: The entire conversation is visible in clear ASCII text.
4. **Capture Encrypted Session**:
   - Start `python server.py` and `python client.py`.
   - Send the same message.
   - Follow TCP Stream in Wireshark.
   - **Observation**: Handshake shows DH public keys; chat messages show base64-encoded encrypted blobs with RSA signatures. The plaintext is completely obfuscated.

---

### B. Nmap (Network Reconnaissance & Port Scanning)

#### Objective
Discover open chat ports, fingerprint running services, and test banner grabbing.

#### Commands to Run Against Server

1. **Standard TCP Port Scan**:
   ```bash
   nmap -p 9999 127.0.0.1
   ```
   *Expected Output*: Port 9999/tcp is reported as `open`.

2. **TCP SYN Stealth Scan**:
   ```bash
   nmap -sS -p 9999 127.0.0.1
   ```
   *Expected Output*: Verifies socket response to raw SYN packets without completing the 3-way handshake.

3. **Service Version & Banner Grabbing**:
   ```bash
   nmap -sV -sC -p 9999 127.0.0.1
   ```
   *Observation*: Nmap attempts protocol probes against CryptoNet's handshake receiver.

---

### C. Hping3 (Packet Crafting & Denial-of-Service Resilience)

#### Objective
Test server socket resilience against SYN floods and malformed TCP packets.

#### Commands (Run on Linux or Kali VM directed at server host IP)

1. **Custom TCP SYN Probe**:
   ```bash
   hping3 -S -p 9999 -c 5 192.168.1.X
   ```
   *Analysis*: Inspect TCP window size and TTL responses from the server socket.

2. **SYN Flood Simulation (Stress Test)**:
   ```bash
   sudo hping3 -S -p 9999 --flood --rand-source 192.168.1.X
   ```
   *Analysis*: Monitor how the Python TCP server responds to queue saturation and evaluate TCP SYN backlog behavior.

---

### D. Snort (Intrusion Detection System Rules)

#### Objective
Write Snort rules to detect unencrypted plaintext leaks vs. authorized encrypted chat traffic.

#### Sample Snort Rules (`snort.rules`)

1. **Detect Plaintext Leaks (Credit card, passwords, confidential tokens in cleartext)**:
   ```snort
   alert tcp any any -> any 9999 (msg:"CRYPTONET - Cleartext Sensitive Keyword Detected"; content:"password"; nocase; sid:1000001; rev:1;)
   ```

2. **Detect Inbound Handshake Connection to CryptoNet Service**:
   ```snort
   alert tcp any any -> any 9999 (msg:"CRYPTONET - Handshake Initiation Observed"; flow:to_server,established; content:"dh_public_key"; sid:1000002; rev:1;)
   ```

3. **Alert on Tampered Packet Flag**:
   ```snort
   alert tcp any any -> any 9999 (msg:"CRYPTONET - Simulated Tampered Payload Detected"; content:"tampered_sim\": true"; sid:1000003; rev:1;)
   ```

---

## Running Automated Tests

To verify all algorithms, key exchanges, ciphers, signatures, and tamper detection without starting a manual chat:

```bash
python test_integration.py
```

To run standalone MD5 performance benchmarks:

```bash
python crypto_utils.py
# or
python server.py --benchmark
```

Benchmark output is logged in structured format to `logs/hash_timing.log`.
