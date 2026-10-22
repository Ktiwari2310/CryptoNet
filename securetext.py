#!/usr/bin/env python3
"""
SecureText — Encrypted File Vault with Integrity Verification
Cryptography & Network Security Lab Project

Author: Khushboo Tiwari
Description:
A single-file Python 3 command-line tool demonstrating:
1. Vernam Cipher (One-Time Pad style stream cipher using bitwise XOR)
2. Deterministic Key Derivation from a password using SHA-256 counter mode
3. Cryptographic Integrity Auditing using MD5 Hashing
4. Man-in-the-Middle (MITM) Tamper Simulation

Pure Python Standard Library only (hashlib, os, sys, time, random, argparse).
No external third-party dependencies required.
"""

import os
import sys
import time
import random
import hashlib
import argparse
from typing import Tuple

# Ensure UTF-8 output encoding across Windows PowerShell, CMD, and Git Bash
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass


# ============================================================================
# 1. KEY DERIVATION FUNCTION (KDF)
# ============================================================================
def derive_keystream(password: str, length: int) -> bytes:
    """
    Derives a pseudo-random keystream of exact byte length `length` from a password.

    Mathematical Concept:
    A true Vernam cipher requires a key stream exactly equal in length to the plaintext.
    To avoid insecure simple repetition (which repeats periodic patterns vulnerable
    to Kasiski examination and frequency analysis), we use SHA-256 in counter mode:
        Keystream = Block_0 || Block_1 || Block_2 ...
        where Block_i = SHA-256(password || counter_i)
    
    This produces a cryptographically pseudo-random keystream indistinguishable
    from random noise, uniquely keyed by the user's password.
    """
    if length <= 0:
        return b""

    password_bytes = password.encode("utf-8")
    keystream = bytearray()
    counter = 0

    while len(keystream) < length:
        # Concatenate password bytes with 4-byte big-endian integer counter
        counter_bytes = counter.to_bytes(4, byteorder="big")
        block = hashlib.sha256(password_bytes + counter_bytes).digest()
        keystream.extend(block)
        counter += 1

    # Return exactly the required number of keystream bytes
    return bytes(keystream[:length])


# ============================================================================
# 2. VERNAM CIPHER (XOR-BASED STREAM CIPHER)
# ============================================================================
def vernam_cipher(data: bytes, keystream: bytes) -> bytes:
    """
    Encrypts or decrypts bytes using Gilbert Vernam's XOR stream cipher (1917).

    Mathematical Foundation:
    Encryption: C[i] = P[i] ⊕ K[i]
    Decryption: P[i] = C[i] ⊕ K[i]

    Because bitwise XOR is its own inverse (A ⊕ B ⊕ B = A), the exact same
    function performs both encryption and decryption.
    """
    if len(data) != len(keystream):
        raise ValueError("Data length and keystream length must be identical for Vernam cipher.")

    # Bitwise XOR each byte of data with the corresponding byte of keystream
    return bytes([b ^ k for b, k in zip(data, keystream)])


# ============================================================================
# 3. MD5 INTEGRITY HASHING & TIMING
# ============================================================================
def compute_md5(data: bytes) -> Tuple[str, float]:
    """
    Computes the 128-bit MD5 message digest of raw bytes and measures
    the execution time in milliseconds with high-precision perf_counter.

    Returns:
        (hex_digest_string, elapsed_time_in_milliseconds)
    """
    start_time = time.perf_counter()
    hasher = hashlib.md5()
    hasher.update(data)
    digest = hasher.hexdigest()
    end_time = time.perf_counter()

    elapsed_ms = (end_time - start_time) * 1000.0
    return digest, elapsed_ms


# ============================================================================
# 4. ENCRYPT MODE
# ============================================================================
def encrypt_file(input_path: str, password: str):
    """
    Encrypts an input file using Vernam cipher and saves:
      1. <input_path>.enc   (encrypted bytes)
      2. <input_path>.hash  (MD5 integrity hash text file)
    """
    if not os.path.isfile(input_path):
        print(f"\n❌ Error: Input file '{input_path}' not found.")
        sys.exit(1)

    if not password:
        print("\n❌ Error: Password cannot be empty.")
        sys.exit(1)

    print("\n" + "=" * 65)
    print("🔐 SECURETEXT — FILE ENCRYPTION PROCESS")
    print("=" * 65)
    print(f"[*] Input File : {input_path}")
    print(f"[*] File Size  : {os.path.getsize(input_path)} bytes")

    # Step 1: Read plaintext
    print("[1/4] Reading input file contents...")
    with open(input_path, "rb") as f:
        plaintext = f.read()

    file_size = len(plaintext)
    if file_size == 0:
        print("⚠️ Warning: Input file is empty. Proceeding with 0-byte encryption.")

    # Step 2: Compute MD5 Integrity Hash of the original plaintext
    print("[2/4] Computing MD5 integrity hash of original plaintext...")
    md5_hash, hash_time_ms = compute_md5(plaintext)
    print(f"      - Original MD5 Hash : {md5_hash}")
    print(f"      - Hash Time Elapsed : {hash_time_ms:.4f} ms")

    # Step 3: Derive Keystream from Password
    print("[3/4] Deriving keystream from password via SHA-256 counter mode...")
    start_kdf = time.perf_counter()
    keystream = derive_keystream(password, file_size)
    kdf_time_ms = (time.perf_counter() - start_kdf) * 1000.0
    print(f"      - Keystream Length  : {len(keystream)} bytes")
    print(f"      - KDF Time Elapsed  : {kdf_time_ms:.4f} ms")

    # Step 4: Vernam Encryption (XOR)
    print("[4/4] Encrypting data with Vernam stream cipher (XOR)...")
    start_enc = time.perf_counter()
    ciphertext = vernam_cipher(plaintext, keystream)
    enc_time_ms = (time.perf_counter() - start_enc) * 1000.0
    total_time_ms = hash_time_ms + kdf_time_ms + enc_time_ms

    # Save output files
    enc_path = f"{input_path}.enc"
    hash_path = f"{input_path}.hash"

    with open(enc_path, "wb") as f:
        f.write(ciphertext)

    with open(hash_path, "w", encoding="utf-8") as f:
        f.write(md5_hash + "\n")

    # Display results
    preview_len = min(16, len(ciphertext))
    preview_hex = " ".join(f"{b:02x}" for b in ciphertext[:preview_len])
    if len(ciphertext) > preview_len:
        preview_hex += " ..."

    print("-" * 65)
    print("✅ ENCRYPTION SUCCESSFUL!")
    print(f"📁 Output Ciphertext File : {enc_path}")
    print(f"📄 Output Integrity Hash  : {hash_path}")
    print(f"🔍 Ciphertext Preview Hex : [{preview_hex}]")
    print(f"⏱️ Total Time Taken       : {total_time_ms:.4f} ms")
    print("=" * 65 + "\n")


# ============================================================================
# 5. DECRYPT MODE
# ============================================================================
def decrypt_file(enc_path: str, password: str):
    """
    Decrypts an encrypted .enc file using the password-derived key,
    recomputes MD5 of decrypted plaintext, compares with .hash file,
    and writes decrypted output to <input_file>.decrypted.
    """
    if not os.path.isfile(enc_path):
        print(f"\n❌ Error: Encrypted file '{enc_path}' not found.")
        sys.exit(1)

    if not password:
        print("\n❌ Error: Password cannot be empty.")
        sys.exit(1)

    # Determine base filename for hash file and output decrypted file
    if enc_path.endswith(".enc"):
        base_name = enc_path[:-4]
    else:
        base_name = enc_path

    hash_path = f"{base_name}.hash"
    decrypted_path = f"{base_name}.decrypted"

    print("\n" + "=" * 65)
    print("🔓 SECURETEXT — FILE DECRYPTION & INTEGRITY CHECK")
    print("=" * 65)
    print(f"[*] Encrypted File : {enc_path}")
    print(f"[*] Expected Hash  : {hash_path}")

    # Read ciphertext
    print("[1/4] Reading encrypted bytes...")
    with open(enc_path, "rb") as f:
        ciphertext = f.read()

    file_size = len(ciphertext)

    # Step 1: Derive Keystream
    print("[2/4] Deriving keystream from password...")
    keystream = derive_keystream(password, file_size)

    # Step 2: Decrypt via Vernam XOR
    print("[3/4] Decrypting bytes via Vernam inverse XOR...")
    decrypted_bytes = vernam_cipher(ciphertext, keystream)

    # Write decrypted output
    with open(decrypted_path, "wb") as f:
        f.write(decrypted_bytes)
    print(f"      - Decrypted content written to: {decrypted_path}")

    # Step 3: Integrity verification via MD5
    print("[4/4] Verifying cryptographic integrity (MD5 hash comparison)...")
    computed_md5, _ = compute_md5(decrypted_bytes)
    print(f"      - Computed MD5 of Decrypted Data : {computed_md5}")

    stored_md5 = None
    if os.path.isfile(hash_path):
        with open(hash_path, "r", encoding="utf-8") as f:
            stored_md5 = f.read().strip()
        print(f"      - Stored Reference MD5 Hash      : {stored_md5}")
    else:
        print(f"      - Stored Reference Hash File     : ⚠️ NOT FOUND ({hash_path})")

    print("-" * 65)
    if stored_md5 and computed_md5.lower() == stored_md5.lower():
        print("✅ Verified — file is untampered")
        print("   The file decrypted perfectly and matches the original cryptographic hash.")
    else:
        print("⚠️ WARNING — file has been modified or wrong password used")
        print("   Integrity verification failed! The decrypted content does NOT match the original.")
    print("=" * 65 + "\n")


# ============================================================================
# 6. TAMPER DEMO MODE
# ============================================================================
def tamper_file(enc_path: str):
    """
    Simulates a Man-in-the-Middle (MITM) or unauthorized modification attack
    by flipping random bytes in the .enc file.
    """
    if not os.path.isfile(enc_path):
        print(f"\n❌ Error: File '{enc_path}' not found.")
        sys.exit(1)

    with open(enc_path, "rb") as f:
        data = bytearray(f.read())

    if len(data) == 0:
        print(f"\n❌ Error: Cannot tamper with an empty file '{enc_path}'.")
        sys.exit(1)

    print("\n" + "=" * 65)
    print("⚠️ SECURETEXT — SIMULATED FILE TAMPER ATTACK")
    print("=" * 65)
    print(f"[*] Target Ciphertext File : {enc_path}")
    print(f"[*] File Size              : {len(data)} bytes")

    # Choose between 1 and 3 random byte positions to flip
    num_flips = min(3, len(data))
    chosen_indices = sorted(random.sample(range(len(data)), num_flips))

    print(f"[*] Modifying {num_flips} byte(s) at random offsets to simulate tampering:")
    for idx in chosen_indices:
        original_byte = data[idx]
        # Invert the byte using bitwise NOT (XOR 0xFF)
        modified_byte = original_byte ^ 0xFF
        data[idx] = modified_byte
        print(f"    - Offset {idx:>4}: 0x{original_byte:02x} -> 0x{modified_byte:02x} (Bitwise Inverted)")

    # Write the tampered content back to the .enc file
    with open(enc_path, "wb") as f:
        f.write(data)

    print("-" * 65)
    print(f"⚠️ TAMPER COMPLETE! '{enc_path}' has been maliciously altered.")
    print("👉 Now run decrypt mode to observe the integrity verification catch the attack:")
    print(f"   python securetext.py decrypt {enc_path} <password>")
    print("=" * 65 + "\n")


# ============================================================================
# 7. COMMAND LINE INTERFACE & MAIN
# ============================================================================
def print_banner():
    print("""
=================================================================
  SecureText — Encrypted File Vault with Integrity Verification
  Cryptography & Network Security Lab Tool
=================================================================
""")


def main():
    parser = argparse.ArgumentParser(
        description="SecureText: Encrypt, Decrypt, and Tamper-Test files using Vernam Cipher and MD5 Integrity Hashing.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples of Usage:
  1. Encrypt a file:
     python securetext.py encrypt secret.txt mypassword123

  2. Decrypt a file:
     python securetext.py decrypt secret.txt.enc mypassword123

  3. Tamper with an encrypted file (demo attack):
     python securetext.py tamper secret.txt.enc

  4. Re-run decrypt to show tampering detected:
     python securetext.py decrypt secret.txt.enc mypassword123
"""
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Encrypt subparser
    enc_parser = subparsers.add_parser("encrypt", help="Encrypt file with Vernam cipher and create MD5 hash")
    enc_parser.add_argument("input_file", help="Path to input file to encrypt")
    enc_parser.add_argument("password", help="Password used to derive encryption keystream")

    # Decrypt subparser
    dec_parser = subparsers.add_parser("decrypt", help="Decrypt .enc file and verify integrity against .hash")
    dec_parser.add_argument("input_file", help="Path to .enc file to decrypt")
    dec_parser.add_argument("password", help="Password used for decryption")

    # Tamper subparser
    tamper_parser = subparsers.add_parser("tamper", help="Flip random bytes in .enc file to simulate tampering")
    tamper_parser.add_argument("input_file", help="Path to .enc file to tamper with")

    if len(sys.argv) == 1:
        print_banner()
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()

    if args.command == "encrypt":
        encrypt_file(args.input_file, args.password)
    elif args.command == "decrypt":
        decrypt_file(args.input_file, args.password)
    elif args.command == "tamper":
        tamper_file(args.input_file)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
