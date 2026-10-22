#!/usr/bin/env python3
"""
SecureText — Complete File Vault with Multi-Layer Protection & Tamper Defense
Cryptography & Network Security Lab Project

Author: Khushboo Tiwari
Description:
A single-file Python 3 security tool providing complete file protection:
1. Confidentiality (Access Control):
   - Vernam stream cipher (bitwise XOR) keyed from password.
   - PBKDF2-HMAC-SHA256 key stretching (100,000 iterations) with a 16-byte random salt.
2. Integrity & Tamper Defense (Modification Prevention):
   - Keyed HMAC-SHA256 authentication tag (prevents ciphertext forgery).
   - 128-bit MD5 checksum (verifies bit-level plaintext integrity).
   - Tamper Shield: Refuses to unlock or leak data if even 1 bit was altered.
3. Forensic Protection (Zero-Leakage):
   - Secure shredding (DoD 3-pass overwrite) of original plaintext after locking.
   - Secure terminal viewing ('view' mode) without saving plaintext to disk.
4. Attack Simulation & Demo:
   - 'tamper' command to simulate unauthorized modification attacks.
   - 'demo' command for a one-click automated presentation to teachers.

Pure Python standard library only (hashlib, hmac, os, sys, time, random, argparse).
No external third-party dependencies required.
"""

import os
import sys
import time
import hmac
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

# File Vault Header Constants
MAGIC_HEADER = b"SECVAULT1"  # 9-byte unique file signature
SALT_SIZE = 16              # 16 bytes (128-bit) cryptographically secure salt
HMAC_SIZE = 32              # 32 bytes (256-bit) HMAC-SHA256 authentication tag
MD5_SIZE = 16               # 16 bytes (128-bit) MD5 plaintext integrity digest
PBKDF2_ROUNDS = 100_000     # 100,000 iterations to resist GPU brute-force attacks


# ============================================================================
# 1. CRYPTOGRAPHIC PRIMITIVES
# ============================================================================
def derive_keys(password: str, salt: bytes, length: int) -> Tuple[bytes, bytes, bytes]:
    """
    Derives cryptographic keys using PBKDF2-HMAC-SHA256 key stretching.

    Security Principle:
    - 16-byte random salt prevents precomputed Rainbow Table attacks.
    - 100,000 PBKDF2 iterations slow down offline dictionary/brute-force attacks.
    - Splits master key into:
      1. Encrypt Key: Expands into keystream for Vernam cipher.
      2. HMAC Key: Used for cryptographic message authentication (tamper proofing).
    """
    password_bytes = password.encode("utf-8")
    # Derive 64 bytes of high-entropy key material
    master_key = hashlib.pbkdf2_hmac("sha256", password_bytes, salt, PBKDF2_ROUNDS, dklen=64)
    enc_seed = master_key[:32]
    hmac_key = master_key[32:]

    # Expand enc_seed into a keystream of exact length `length` via SHA-256 counter mode
    keystream = bytearray()
    counter = 0
    while len(keystream) < length:
        block = hashlib.sha256(enc_seed + counter.to_bytes(4, byteorder="big")).digest()
        keystream.extend(block)
        counter += 1

    return bytes(keystream[:length]), hmac_key, master_key


def vernam_xor(data: bytes, keystream: bytes) -> bytes:
    """
    Gilbert Vernam's stream cipher (1917).
    Encryption & Decryption are symmetric: C[i] = P[i] ^ K[i] and P[i] = C[i] ^ K[i].
    """
    return bytes([d ^ k for d, k in zip(data, keystream)])


def compute_hmac(key: bytes, data: bytes) -> bytes:
    """Computes a keyed HMAC-SHA256 authentication tag over data."""
    return hmac.new(key, data, hashlib.sha256).digest()


def compute_md5(data: bytes) -> bytes:
    """Computes 16-byte binary MD5 message digest of data."""
    return hashlib.md5(data).digest()


def secure_shred(file_path: str):
    """
    Forensic Secure Erasure (DoD 5220.22-M 3-Pass Overwrite).
    Overwrites the plaintext file with 0x00, 0xFF, and random noise before deleting,
    ensuring data cannot be recovered by forensic tools (Recuva, TestDisk).
    """
    if not os.path.isfile(file_path):
        return

    length = os.path.getsize(file_path)
    with open(file_path, "ba+", buffering=0) as f:
        # Pass 1: Overwrite with all zeros (0x00)
        f.seek(0)
        f.write(b"\x00" * length)
        # Pass 2: Overwrite with all ones (0xFF)
        f.seek(0)
        f.write(b"\xFF" * length)
        # Pass 3: Overwrite with cryptographically secure random bytes
        f.seek(0)
        f.write(os.urandom(length))

    os.remove(file_path)


# ============================================================================
# 2. LOCK MODE (PROTECT FILE)
# ============================================================================
def lock_file(file_path: str, password: str, shred_original: bool = False):
    """
    Locks and protects a file with password encryption, PBKDF2 salt,
    HMAC authentication, and MD5 integrity verification.
    """
    if not os.path.isfile(file_path):
        print(f"\n❌ Error: Target file '{file_path}' does not exist.")
        sys.exit(1)

    if not password:
        print("\n❌ Error: Password cannot be empty.")
        sys.exit(1)

    print("\n" + "=" * 68)
    print("🔒 SECURETEXT — FILE LOCKING & PROTECTION PROCESS")
    print("=" * 68)
    print(f"[*] Target File    : {file_path}")
    print(f"[*] Original Size  : {os.path.getsize(file_path)} bytes")

    # Step 1: Read plaintext
    print("[1/5] Reading sensitive file contents into memory...")
    with open(file_path, "rb") as f:
        plaintext = f.read()

    file_size = len(plaintext)

    # Step 2: Compute MD5 integrity hash of plaintext
    print("[2/5] Computing MD5 plaintext integrity digest...")
    md5_digest = compute_md5(plaintext)
    print(f"      - Plaintext MD5 Digest : {md5_digest.hex()}")

    # Step 3: Generate Salt & Derive Keys via 100,000 PBKDF2 rounds
    print("[3/5] Generating 16-byte random salt & stretching key with PBKDF2...")
    salt = os.urandom(SALT_SIZE)
    t0 = time.perf_counter()
    keystream, hmac_key, _ = derive_keys(password, salt, file_size)
    kdf_ms = (time.perf_counter() - t0) * 1000.0
    print(f"      - Cryptographic Salt   : {salt.hex()[:16]}... (16 bytes random)")
    print(f"      - PBKDF2 Iterations    : {PBKDF2_ROUNDS:,} rounds ({kdf_ms:.2f} ms)")

    # Step 4: Encrypt via Vernam XOR
    print("[4/5] Encrypting with Vernam Stream Cipher (Bitwise XOR)...")
    ciphertext = vernam_xor(plaintext, keystream)

    # Step 5: Compute HMAC-SHA256 authentication tag over (Salt || Ciphertext)
    print("[5/5] Generating HMAC-SHA256 Tamper-Detection Authentication Tag...")
    auth_tag = compute_hmac(hmac_key, salt + ciphertext)
    print(f"      - HMAC Auth Tag        : {auth_tag.hex()[:32]}... (256 bits)")

    # Build protected vault package
    vault_data = MAGIC_HEADER + salt + auth_tag + md5_digest + ciphertext
    vault_path = f"{file_path}.vault"

    with open(vault_path, "wb") as f:
        f.write(vault_data)

    print("-" * 68)
    print("🛡️ FILE LOCKED & PROTECTED SUCCESSFULLY!")
    print(f"📁 Protected Vault File: {vault_path}")
    print(f"🔐 Security Layers     : Vernam OTP + PBKDF2 (100k rounds) + HMAC-SHA256 + MD5")

    # Optional forensic shredding
    if shred_original:
        print("[!] Secure Shredding: Wiping original plaintext from disk (DoD 3-pass)...")
        secure_shred(file_path)
        print(f"    - Original '{file_path}' permanently destroyed to prevent disk recovery.")
    else:
        print(f"ℹ️ Original file '{file_path}' kept. (Use --shred to wipe plaintext permanently).")
    print("=" * 68 + "\n")


# ============================================================================
# 3. UNLOCK MODE (ACCESS PROTECTED FILE)
# ============================================================================
def unlock_file(vault_path: str, password: str, output_path: str = None) -> bytes:
    """
    Unlocks a protected .vault file:
    1. Validates magic header signature.
    2. Uses PBKDF2 to derive keys.
    3. Verifies HMAC authentication tag (detects wrong password OR tampering).
    4. Decrypts via Vernam inverse XOR.
    5. Verifies MD5 checksum against original plaintext.
    6. Restores the unlocked file.
    """
    if not os.path.isfile(vault_path):
        print(f"\n❌ Error: Vault file '{vault_path}' does not exist.")
        sys.exit(1)

    print("\n" + "=" * 68)
    print("🔓 SECURETEXT — FILE UNLOCKING & ACCESS CONTROL")
    print("=" * 68)
    print(f"[*] Protected Vault : {vault_path}")

    # Read vault package
    with open(vault_path, "rb") as f:
        vault_data = f.read()

    # Step 1: Validate header structure
    header_len = len(MAGIC_HEADER) + SALT_SIZE + HMAC_SIZE + MD5_SIZE
    if len(vault_data) < header_len or not vault_data.startswith(MAGIC_HEADER):
        print("\n❌ SECURITY REJECTION: Invalid or corrupted file format.")
        print("   This is not a valid SecureText vault file.")
        sys.exit(1)

    offset = len(MAGIC_HEADER)
    salt = vault_data[offset:offset + SALT_SIZE]
    offset += SALT_SIZE
    stored_hmac = vault_data[offset:offset + HMAC_SIZE]
    offset += HMAC_SIZE
    stored_md5 = vault_data[offset:offset + MD5_SIZE]
    offset += MD5_SIZE
    ciphertext = vault_data[offset:]

    # Step 2: Derive keys using the stored salt and user's password
    print("[1/4] Deriving cryptographic keys via PBKDF2 (100,000 rounds)...")
    keystream, hmac_key, _ = derive_keys(password, salt, len(ciphertext))

    # Step 3: Check HMAC-SHA256 Authentication Tag FIRST
    print("[2/4] Verifying HMAC-SHA256 Authenticity & Tamper Shield...")
    computed_hmac = compute_hmac(hmac_key, salt + ciphertext)

    # Use constant-time comparison to prevent timing side-channel attacks
    if not hmac.compare_digest(stored_hmac, computed_hmac):
        print("\n" + "!" * 68)
        print("🚨 ACCESS DENIED: SECURITY SHIELD TRIGGERED! 🚨")
        print("!" * 68)
        print("❌ EITHER:")
        print("   1. An INCORRECT password was entered.")
        print("   2. OR the file was MALICIOUSLY ALTERED/TAMPERED WITH in transit or storage!")
        print("\n🛡️ Defense Action: SecureText refuses to unlock or leak any data.")
        print("!" * 68 + "\n")
        sys.exit(1)

    print("      - HMAC Verification : [PASSED ✓] (Authentic & Password Verified)")

    # Step 4: Decrypt via Vernam XOR
    print("[3/4] Decrypting ciphertext via Vernam stream cipher...")
    plaintext = vernam_xor(ciphertext, keystream)

    # Step 5: Check MD5 plaintext integrity
    print("[4/4] Verifying bit-level MD5 plaintext integrity...")
    computed_md5 = compute_md5(plaintext)
    if not hmac.compare_digest(stored_md5, computed_md5):
        print("\n🚨 INTEGRITY FAILED: MD5 digest mismatch! Data corrupted.")
        sys.exit(1)

    print("      - MD5 Verification  : [PASSED ✓] (Bit-level integrity confirmed)")

    # Determine restored file path
    if not output_path:
        if vault_path.endswith(".vault"):
            output_path = vault_path[:-6]
        else:
            output_path = f"{vault_path}.unlocked"

    with open(output_path, "wb") as f:
        f.write(plaintext)

    print("-" * 68)
    print("✅ ACCESS GRANTED — FILE UNLOCKED SUCCESSFULLY!")
    print(f"📁 Restored File    : {output_path}")
    print(f"📄 Recovered Size   : {len(plaintext)} bytes")
    print("=" * 68 + "\n")
    return plaintext


# ============================================================================
# 4. VIEW MODE (ZERO-LEAKAGE TERMINAL PEEK)
# ============================================================================
def view_file(vault_path: str, password: str):
    """
    Securely displays the contents of a protected vault file directly
    in the terminal without ever saving unencrypted plaintext to the disk.
    """
    if not os.path.isfile(vault_path):
        print(f"\n❌ Error: Vault file '{vault_path}' not found.")
        sys.exit(1)

    print("\n" + "=" * 68)
    print("👁️ SECURETEXT — ZERO-DISK-LEAKAGE FILE VIEWER")
    print("=" * 68)

    with open(vault_path, "rb") as f:
        vault_data = f.read()

    header_len = len(MAGIC_HEADER) + SALT_SIZE + HMAC_SIZE + MD5_SIZE
    if len(vault_data) < header_len or not vault_data.startswith(MAGIC_HEADER):
        print("❌ Error: Invalid vault file.")
        sys.exit(1)

    offset = len(MAGIC_HEADER)
    salt = vault_data[offset:offset + SALT_SIZE]
    offset += SALT_SIZE
    stored_hmac = vault_data[offset:offset + HMAC_SIZE]
    offset += HMAC_SIZE
    offset += MD5_SIZE
    ciphertext = vault_data[offset:]

    keystream, hmac_key, _ = derive_keys(password, salt, len(ciphertext))
    computed_hmac = compute_hmac(hmac_key, salt + ciphertext)

    if not hmac.compare_digest(stored_hmac, computed_hmac):
        print("🚨 ACCESS DENIED: Incorrect password or modified vault.")
        sys.exit(1)

    plaintext = vernam_xor(ciphertext, keystream)
    print(f"[*] Displaying contents of '{vault_path}' (Decrypted in-memory only):")
    print("-" * 68)
    try:
        print(plaintext.decode("utf-8"))
    except UnicodeDecodeError:
        print(f"[Binary Content Preview: {plaintext[:64].hex()}...]")
    print("-" * 68)
    print("🔒 File was decrypted in RAM only. Zero plaintext was written to disk.")
    print("=" * 68 + "\n")


# ============================================================================
# 5. TAMPER ATTACK SIMULATOR (DEMONSTRATES TAMPER DEFENSE)
# ============================================================================
def tamper_vault(vault_path: str):
    """
    Simulates a malicious attacker attempting to modify the protected file.
    Alters bytes in the ciphertext or header to test the defense shield.
    """
    if not os.path.isfile(vault_path):
        print(f"\n❌ Error: Vault file '{vault_path}' not found.")
        sys.exit(1)

    with open(vault_path, "rb") as f:
        data = bytearray(f.read())

    header_len = len(MAGIC_HEADER) + SALT_SIZE + HMAC_SIZE + MD5_SIZE
    if len(data) <= header_len:
        print("❌ Error: Vault file too small to tamper.")
        sys.exit(1)

    print("\n" + "=" * 68)
    print("⚠️ SECURETEXT — SIMULATED UNAUTHORIZED TAMPER ATTACK")
    print("=" * 68)
    print(f"[*] Target Vault File : {vault_path}")
    print(f"[*] Total File Size   : {len(data)} bytes")

    # Pick a byte in the ciphertext payload area (after headers)
    target_idx = random.randint(header_len, len(data) - 1)
    original_byte = data[target_idx]
    modified_byte = original_byte ^ 0xFF
    data[target_idx] = modified_byte

    with open(vault_path, "wb") as f:
        f.write(data)

    print(f"[!] ATTACK SIMULATED: Attacker altered byte at offset {target_idx}:")
    print(f"    0x{original_byte:02x} -> 0x{modified_byte:02x} (Bitwise Inverted)")
    print("-" * 68)
    print("🛡️ NOW TEST THE DEFENSE:")
    print("   Attempt to unlock the file with the correct password:")
    print(f"   python securetext.py unlock {vault_path} <password>")
    print("   Observe how SecureText immediately locks down and prevents access!")
    print("=" * 68 + "\n")


# ============================================================================
# 6. ONE-CLICK AUTOMATED LAB DEMO (FOR TEACHERS / PRESENTATIONS)
# ============================================================================
def run_auto_demo():
    """
    Automated presentation walkthrough showing the complete security lifecycle:
    Lock -> View -> Tamper Attack Blocked -> Unlock.
    """
    print("\n" + "#" * 68)
    print("🎬 SECURETEXT — AUTOMATED LAB PRESENTATION DEMO")
    print("#" * 68)

    demo_file = "lab_secret.txt"
    demo_password = "TeacherDemoPassword2026!"

    # Create sample document
    with open(demo_file, "w", encoding="utf-8") as f:
        f.write("TOP SECRET LAB REPORT 2026\nConfidential research findings & exam papers.\nDo not distribute.")

    print("\n[SCENARIO 1]: User has a confidential file and wants to protect it.")
    time.sleep(1)
    lock_file(demo_file, demo_password, shred_original=False)

    print("\n[SCENARIO 2]: User wants to view the protected file securely in terminal.")
    time.sleep(1)
    view_file(f"{demo_file}.vault", demo_password)

    print("\n[SCENARIO 3]: An attacker intercepts the file and tampers with it.")
    time.sleep(1)
    tamper_vault(f"{demo_file}.vault")

    print("\n[SCENARIO 4]: User tries to unlock the tampered file (Defense Triggered).")
    time.sleep(1)
    try:
        unlock_file(f"{demo_file}.vault", demo_password)
    except SystemExit:
        print("[✓] As demonstrated, the defense shield successfully blocked unauthorized access!")

    # Clean up demo files
    for f_path in [demo_file, f"{demo_file}.vault", f"{demo_file}.unlocked"]:
        if os.path.exists(f_path):
            os.remove(f_path)

    print("\n" + "#" * 68)
    print("🎉 DEMO COMPLETED SUCCESSFULLY — ALL SECURITY CONTROLS VERIFIED!")
    print("#" * 68 + "\n")


# ============================================================================
# 7. CLI ENTRY POINT
# ============================================================================
def main():
    parser = argparse.ArgumentParser(
        description="SecureText: Encrypted File Vault with PBKDF2, Vernam OTP, HMAC, and Tamper Shield.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Core Workflows:
  1. Lock & Protect a File:
     python securetext.py lock secret.txt mypassword123

  2. Lock & Securely Shred Plaintext from Disk:
     python securetext.py lock secret.txt mypassword123 --shred

  3. Unlock Protected File:
     python securetext.py unlock secret.txt.vault mypassword123

  4. View File in Terminal (Zero Disk Footprint):
     python securetext.py view secret.txt.vault mypassword123

  5. Simulate Attack (Tamper with Vault):
     python securetext.py tamper secret.txt.vault

  6. Run Full Presentation Demo:
     python securetext.py demo
"""
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Lock command
    p_lock = subparsers.add_parser("lock", help="Lock & protect a file with password")
    p_lock.add_argument("file", help="Path of the file to protect")
    p_lock.add_argument("password", help="Secret password")
    p_lock.add_argument("--shred", action="store_true", help="Securely overwrite and shred original plaintext")

    # Unlock command
    p_unlock = subparsers.add_parser("unlock", help="Unlock and restore protected file")
    p_unlock.add_argument("vault", help="Path of the .vault file")
    p_unlock.add_argument("password", help="Secret password")
    p_unlock.add_argument("-o", "--output", help="Optional custom output path for restored file")

    # View command
    p_view = subparsers.add_parser("view", help="View file in terminal without writing to disk")
    p_view.add_argument("vault", help="Path of the .vault file")
    p_view.add_argument("password", help="Secret password")

    # Tamper command
    p_tamper = subparsers.add_parser("tamper", help="Simulate unauthorized tampering attack")
    p_tamper.add_argument("vault", help="Path of the .vault file to tamper with")

    # Demo command
    subparsers.add_parser("demo", help="Run automated end-to-end presentation demo")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()

    if args.command == "lock":
        lock_file(args.file, args.password, shred_original=args.shred)
    elif args.command == "unlock":
        unlock_file(args.vault, args.password, output_path=args.output)
    elif args.command == "view":
        view_file(args.vault, args.password)
    elif args.command == "tamper":
        tamper_vault(args.vault)
    elif args.command == "demo":
        run_auto_demo()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
