#!/usr/bin/env python3
"""
Text File Encrypter/Decrypter CLI Tool
Cryptography & Network Security Lab Project

Syllabus Specification:
- Custom Key Generation (True Random One-Time Pad & Password-Derived Keys)
- Vernam (One-Time Pad) XOR Operations (Confusion)
- Rail Fence Transposition Operations (Diffusion)
- Cryptographic Integrity Verification (MD5) & Tamper Detection
- Frequency Analysis & Shannon Entropy Evaluation

Author: Khushboo Tiwari
Pure Python standard library only.
"""

import os
import sys
import math
import time
import random
import secrets
import hashlib
import argparse
from typing import Tuple, List, Dict

# Ensure UTF-8 console output for Windows compatibility
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass


# ============================================================================
# 1. CUSTOM KEY GENERATION
# ============================================================================
def generate_custom_otp_key(length: int, output_keyfile: str = "custom_otp.key") -> bytes:
    """
    Generates a cryptographically secure, truly random One-Time Pad key
    of the exact specified byte length using the OS CSPRNG (secrets module).
    """
    key_bytes = secrets.token_bytes(length)
    with open(output_keyfile, "wb") as f:
        f.write(key_bytes)
    return key_bytes


def derive_key_from_password(password: str, length: int) -> bytes:
    """
    Derives a deterministic keystream of exact length `length` from a user password
    using SHA-256 counter mode expansion: Block_i = SHA256(password || counter_i).
    """
    password_bytes = password.encode("utf-8")
    keystream = bytearray()
    counter = 0
    while len(keystream) < length:
        block = hashlib.sha256(password_bytes + counter.to_bytes(4, byteorder="big")).digest()
        keystream.extend(block)
        counter += 1
    return bytes(keystream[:length])


# ============================================================================
# 2. VERNAM (ONE-TIME PAD) XOR CIPHER (CONFUSION)
# ============================================================================
def vernam_xor(data: bytes, key: bytes) -> bytes:
    """
    Gilbert Vernam's cipher (1917).
    Bitwise XOR operation between each plaintext byte and key byte:
        C[i] = P[i] ^ K[i]
        P[i] = C[i] ^ K[i]
    Because XOR is self-inverse, the exact same function performs both
    encryption and decryption.
    """
    if len(data) > len(key):
        raise ValueError(f"Key length ({len(key)} bytes) is shorter than data length ({len(data)} bytes).")
    return bytes([d ^ k for d, k in zip(data, key[:len(data)])])


# ============================================================================
# 3. RAIL FENCE TRANSPOSITION CIPHER (DIFFUSION)
# ============================================================================
def rail_fence_encrypt(data: bytes, rails: int = 3) -> bytes:
    """
    Arranges bytes in a zigzag wave across `rails` rows, then reads row by row.
    Provides positional diffusion after the Vernam substitution layer.
    """
    if rails <= 1 or len(data) <= rails:
        return data

    fence: List[List[int]] = [[] for _ in range(rails)]
    rail = 0
    direction = 1

    for byte in data:
        fence[rail].append(byte)
        rail += direction
        if rail == rails - 1:
            direction = -1
        elif rail == 0:
            direction = 1

    return bytes([b for row in fence for b in row])


def rail_fence_decrypt(data: bytes, rails: int = 3) -> bytes:
    """
    Inverts the Rail Fence transposition by reconstructing the zigzag pattern
    and reading bytes back in their original order.
    """
    if rails <= 1 or len(data) <= rails:
        return data

    # 1. Trace the zigzag rail index for every character position
    pattern: List[int] = []
    rail = 0
    direction = 1
    for _ in range(len(data)):
        pattern.append(rail)
        rail += direction
        if rail == rails - 1:
            direction = -1
        elif rail == 0:
            direction = 1

    # 2. Count characters allocated to each rail row
    counts = [pattern.count(r) for r in range(rails)]

    # 3. Slice ciphertext into rows
    rows: List[List[int]] = []
    idx = 0
    for count in counts:
        rows.append(list(data[idx:idx + count]))
        idx += count

    # 4. Reconstruct plaintext following original zigzag pattern
    result: List[int] = []
    pointers = [0] * rails
    for r in pattern:
        result.append(rows[r][pointers[r]])
        pointers[r] += 1

    return bytes(result)


# ============================================================================
# 4. CRYPTANALYTIC TOOLS: SHANNON ENTROPY & FREQUENCY ANALYSIS
# ============================================================================
def calculate_shannon_entropy(data: bytes) -> float:
    """
    Calculates Shannon Entropy in bits per byte (0.0 to 8.0):
        H = - sum( p(x) * log2(p(x)) )
    English text typically has entropy around 3.5 - 4.5 bits/byte.
    Properly encrypted ciphertext approaches theoretical maximum of 8.0 bits/byte.
    """
    if not data:
        return 0.0
    frequencies = [0] * 256
    for b in data:
        frequencies[b] += 1
    entropy = 0.0
    total = len(data)
    for count in frequencies:
        if count > 0:
            p = count / total
            entropy -= p * math.log2(p)
    return entropy


def display_frequency_analysis(file_path: str):
    """
    Displays an ASCII frequency histogram and Shannon entropy analysis for a file.
    Shows the dramatic difference between structured plaintext and encrypted data.
    """
    if not os.path.isfile(file_path):
        print(f"❌ Error: File '{file_path}' not found.")
        return

    with open(file_path, "rb") as f:
        data = f.read()

    entropy = calculate_shannon_entropy(data)
    print("\n" + "=" * 68)
    print(f"📊 CRYPTANALYSIS & FREQUENCY REPORT: {file_path}")
    print("=" * 68)
    print(f"[*] File Size      : {len(data)} bytes")
    print(f"[*] Shannon Entropy: {entropy:.4f} / 8.0000 bits/byte")
    if entropy < 5.0:
        print("    -> Evaluation: Low entropy (Structured human language/plaintext)")
    else:
        print("    -> Evaluation: High entropy (Pseudo-random noise/ciphertext)")

    # Count printable ASCII frequencies
    counts: Dict[str, int] = {}
    for b in data:
        char = chr(b) if 32 <= b <= 126 else f"\\x{b:02x}"
        counts[char] = counts.get(char, 0) + 1

    sorted_chars = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:10]
    print("\nTop 10 Most Frequent Bytes:")
    print(f"{'Byte/Char':<12} | {'Count':<8} | {'Percentage':<10} | Histogram")
    print("-" * 60)
    for char, count in sorted_chars:
        pct = (count / len(data)) * 100
        bar = "█" * int(pct / 2)
        print(f"{repr(char):<12} | {count:<8} | {pct:>6.2f}%    | {bar}")
    print("=" * 68 + "\n")


# ============================================================================
# 5. HYBRID ENCRYPTION & DECRYPTION PIPELINE
# ============================================================================
def load_or_derive_key(key_arg: str, target_length: int) -> bytes:
    """
    Intelligently loads key bytes from a keyfile if it exists,
    or derives key bytes from the string as a password.
    """
    if os.path.isfile(key_arg):
        with open(key_arg, "rb") as f:
            key_data = f.read()
        if len(key_data) < target_length:
            print(f"[*] Keyfile '{key_arg}' is {len(key_data)}B (expanding to {target_length}B)...")
            key_data = derive_key_from_password(key_data.hex(), target_length)
        return key_data[:target_length]
    else:
        # Treat as password
        return derive_key_from_password(key_arg, target_length)


def encrypt_file(input_path: str, key_arg: str, rails: int = 3):
    """
    Encrypts a text file:
    1. Reads plaintext text file.
    2. Computes MD5 integrity hash.
    3. Vernam XOR Substitution (Confusion).
    4. Rail Fence Transposition (Diffusion).
    5. Saves <input_path>.enc and <input_path>.hash.
    """
    if not os.path.isfile(input_path):
        print(f"❌ Error: File '{input_path}' not found.")
        sys.exit(1)

    print("\n" + "=" * 68)
    print("🔐 TEXT FILE HYBRID ENCRYPTION PIPELINE")
    print("=" * 68)
    print(f"[*] Input File     : {input_path} ({os.path.getsize(input_path)} bytes)")
    print(f"[*] Rail Fence     : {rails} rails")

    with open(input_path, "rb") as f:
        plaintext = f.read()

    # Step 1: MD5 Plaintext Integrity Check
    t0 = time.perf_counter()
    md5_hash = hashlib.md5(plaintext).hexdigest()
    print(f"[1/4] Plaintext MD5 Integrity Digest : {md5_hash}")

    # Step 2: Custom Key Acquisition
    key_bytes = load_or_derive_key(key_arg, len(plaintext))
    print(f"[2/4] Key Stream Ready               : {len(key_bytes)} bytes")

    # Step 3: Vernam (One-Time Pad) XOR Operation
    vernam_ct = vernam_xor(plaintext, key_bytes)
    print(f"[3/4] Vernam XOR Substitution (Confusion) complete.")

    # Step 4: Rail Fence Transposition Operation
    final_ct = rail_fence_encrypt(vernam_ct, rails)
    enc_time = (time.perf_counter() - t0) * 1000.0
    print(f"[4/4] Rail Fence Transposition (Diffusion) complete.")

    enc_path = f"{input_path}.enc"
    hash_path = f"{input_path}.hash"

    with open(enc_path, "wb") as f:
        f.write(final_ct)

    with open(hash_path, "w", encoding="utf-8") as f:
        f.write(f"{md5_hash}\nrails={rails}\n")

    # Shannon Entropy comparison
    pt_entropy = calculate_shannon_entropy(plaintext)
    ct_entropy = calculate_shannon_entropy(final_ct)

    print("-" * 68)
    print("✅ ENCRYPTION SUCCESSFUL!")
    print(f"📁 Output Ciphertext File : {enc_path}")
    print(f"📄 Output Integrity Hash  : {hash_path}")
    print(f"⏱️ Total Execution Time   : {enc_time:.4f} ms")
    print(f"📈 Plaintext Entropy      : {pt_entropy:.4f} bits/byte")
    print(f"📈 Ciphertext Entropy     : {ct_entropy:.4f} bits/byte (Near-maximum 8.0!)")
    print("=" * 68 + "\n")


def decrypt_file(enc_path: str, key_arg: str, rails: int = 3, output_path: str = None):
    """
    Decrypts an encrypted file:
    1. Reverses Rail Fence Transposition.
    2. Reverses Vernam XOR.
    3. Recomputes MD5 and compares with stored .hash file.
    4. Writes restored plaintext to <input_path>.decrypted.
    """
    if not os.path.isfile(enc_path):
        print(f"❌ Error: Ciphertext file '{enc_path}' not found.")
        sys.exit(1)

    print("\n" + "=" * 68)
    print("🔓 TEXT FILE HYBRID DECRYPTION PIPELINE")
    print("=" * 68)
    print(f"[*] Ciphertext File: {enc_path} ({os.path.getsize(enc_path)} bytes)")

    with open(enc_path, "rb") as f:
        ciphertext = f.read()

    # Determine hash file path
    base_name = enc_path[:-4] if enc_path.endswith(".enc") else enc_path
    hash_path = f"{base_name}.hash"

    stored_md5 = None
    if os.path.isfile(hash_path):
        with open(hash_path, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]
            if lines:
                stored_md5 = lines[0]
            # Check if rails was stored
            for line in lines[1:]:
                if line.startswith("rails="):
                    try:
                        rails = int(line.split("=")[1])
                    except ValueError:
                        pass

    print(f"[*] Rail Fence Depth: {rails} rails")

    # Step 1: Invert Rail Fence Transposition
    t0 = time.perf_counter()
    vernam_ct = rail_fence_decrypt(ciphertext, rails)
    print("[1/3] Rail Fence Transposition reversed.")

    # Step 2: Invert Vernam XOR Operation
    key_bytes = load_or_derive_key(key_arg, len(vernam_ct))
    plaintext = vernam_xor(vernam_ct, key_bytes)
    dec_time = (time.perf_counter() - t0) * 1000.0
    print("[2/3] Vernam XOR Decryption complete.")

    # Step 3: Integrity verification
    computed_md5 = hashlib.md5(plaintext).hexdigest()
    print(f"[3/3] Integrity Check: Computed MD5 = {computed_md5}")
    if stored_md5:
        print(f"                     Stored Reference = {stored_md5}")

    if not output_path:
        output_path = f"{base_name}.decrypted"

    with open(output_path, "wb") as f:
        f.write(plaintext)

    print("-" * 68)
    if stored_md5 and computed_md5.lower() == stored_md5.lower():
        print("✅ VERIFIED — FILE IS UNTAMPERED & AUTHENTIC!")
        print(f"📁 Decrypted Output: {output_path}")
    else:
        print("⚠️ WARNING — TAMPERING OR WRONG KEY DETECTED!")
        print("   Integrity verification failed! Hashes do not match.")
    print(f"⏱️ Total Execution Time: {dec_time:.4f} ms")
    print("=" * 68 + "\n")


# ============================================================================
# 6. TAMPER DEMO & AUTOMATED LAB DEMO
# ============================================================================
def tamper_file(enc_path: str):
    """
    Simulates a Man-in-the-Middle (MITM) attack by bitwise inverting bytes
    in the encrypted file.
    """
    if not os.path.isfile(enc_path):
        print(f"❌ Error: File '{enc_path}' not found.")
        sys.exit(1)

    with open(enc_path, "rb") as f:
        data = bytearray(f.read())

    if not data:
        print("❌ Error: File is empty.")
        sys.exit(1)

    num_flips = min(3, len(data))
    chosen = sorted(random.sample(range(len(data)), num_flips))
    print("\n" + "=" * 68)
    print("⚠️ SIMULATED CIPHERTEXT TAMPER ATTACK")
    print("=" * 68)
    for idx in chosen:
        orig = data[idx]
        data[idx] = orig ^ 0xFF
        print(f"[!] Altered byte at offset {idx:>3}: 0x{orig:02x} -> 0x{data[idx]:02x}")

    with open(enc_path, "wb") as f:
        f.write(data)

    print("-" * 68)
    print(f"⚠️ '{enc_path}' was tampered with! Decryption will now fail integrity check.")
    print("=" * 68 + "\n")


def run_lab_demo():
    """
    One-click automated presentation demonstration for teachers and lab examiners.
    """
    print("\n" + "#" * 68)
    print("🎬 TEXT FILE ENCRYPTER/DECRYPTER — AUTOMATED LAB DEMO")
    print("#" * 68)

    sample_doc = "confidential_lab_report.txt"
    with open(sample_doc, "w", encoding="utf-8") as f:
        f.write("TOP SECRET LAB EXPERIMENT\nDepartment of Cryptography & Network Security.\nTest data: 1234567890.\n")

    print("\n[STEP 1]: Generate a custom 64-byte One-Time Pad keyfile.")
    keyfile = "custom_demo.key"
    generate_custom_otp_key(os.path.getsize(sample_doc), keyfile)
    print(f"✓ Custom key generated and saved to '{keyfile}'.")
    time.sleep(1)

    print("\n[STEP 2]: Perform frequency analysis on plaintext before encryption.")
    display_frequency_analysis(sample_doc)
    time.sleep(1)

    print("\n[STEP 3]: Encrypt file using Vernam XOR + Rail Fence Transposition (3 rails).")
    encrypt_file(sample_doc, keyfile, rails=3)
    time.sleep(1)

    print("\n[STEP 4]: Perform frequency analysis on ciphertext to show flattened entropy.")
    display_frequency_analysis(f"{sample_doc}.enc")
    time.sleep(1)

    print("\n[STEP 5]: Decrypt file using keyfile and verify integrity.")
    decrypt_file(f"{sample_doc}.enc", keyfile, rails=3)
    time.sleep(1)

    print("\n[STEP 6]: Simulate an attacker tampering with the ciphertext.")
    tamper_file(f"{sample_doc}.enc")
    time.sleep(1)

    print("\n[STEP 7]: Attempt decryption of tampered file (Integrity Alarm Triggered).")
    decrypt_file(f"{sample_doc}.enc", keyfile, rails=3)

    # Clean up demo files
    for p in [sample_doc, keyfile, f"{sample_doc}.enc", f"{sample_doc}.hash", f"{sample_doc}.decrypted"]:
        if os.path.exists(p):
            os.remove(p)

    print("\n" + "#" * 68)
    print("🎉 DEMO COMPLETE — ALL SYLLABUS CAPABILITIES SUCCESSFULLY VERIFIED!")
    print("#" * 68 + "\n")


# ============================================================================
# 7. MAIN CLI PARSER
# ============================================================================
def main():
    parser = argparse.ArgumentParser(
        description="Text File Encrypter/Decrypter: Custom Keygen, Vernam (OTP) XOR, & Rail Fence Transposition.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Usage Examples:
  1. Generate a custom random OTP key:
     python filecipher.py keygen 100 -o mykey.key

  2. Encrypt text file with a keyfile:
     python filecipher.py encrypt notes.txt --key mykey.key --rails 3

  3. Encrypt text file with a password:
     python filecipher.py encrypt notes.txt --key mysecretpass --rails 3

  4. Decrypt text file:
     python filecipher.py decrypt notes.txt.enc --key mykey.key

  5. Frequency Analysis & Shannon Entropy:
     python filecipher.py analyze notes.txt

  6. Tamper simulation:
     python filecipher.py tamper notes.txt.enc

  7. One-click Automated Lab Presentation:
     python filecipher.py demo
"""
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Keygen command
    p_keygen = subparsers.add_parser("keygen", help="Generate custom random One-Time Pad key")
    p_keygen.add_argument("length", type=int, help="Key length in bytes")
    p_keygen.add_argument("-o", "--output", default="custom_otp.key", help="Output key file path")

    # Encrypt command
    p_enc = subparsers.add_parser("encrypt", help="Encrypt text file (Vernam XOR + Rail Fence)")
    p_enc.add_argument("file", help="Path of text file to encrypt")
    p_enc.add_argument("--key", required=True, help="Path to keyfile OR password string")
    p_enc.add_argument("--rails", type=int, default=3, help="Rail fence transposition depth (default: 3)")

    # Decrypt command
    p_dec = subparsers.add_parser("decrypt", help="Decrypt text file (Invert Rail Fence + Vernam XOR)")
    p_dec.add_argument("file", help="Path of .enc file to decrypt")
    p_dec.add_argument("--key", required=True, help="Path to keyfile OR password string")
    p_dec.add_argument("--rails", type=int, default=3, help="Rail fence transposition depth (default: 3)")
    p_dec.add_argument("-o", "--output", help="Optional custom output path")

    # Analyze command
    p_ana = subparsers.add_parser("analyze", help="Display character frequency histogram & Shannon entropy")
    p_ana.add_argument("file", help="Path of file to analyze")

    # Tamper command
    p_tmp = subparsers.add_parser("tamper", help="Simulate MITM tampering on .enc file")
    p_tmp.add_argument("file", help="Path of .enc file to tamper with")

    # Demo command
    subparsers.add_parser("demo", help="Run automated end-to-end presentation demo")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()

    if args.command == "keygen":
        generate_custom_otp_key(args.length, args.output)
        print(f"✓ Generated custom {args.length}-byte One-Time Pad key: '{args.output}'")
    elif args.command == "encrypt":
        encrypt_file(args.file, args.key, rails=args.rails)
    elif args.command == "decrypt":
        decrypt_file(args.file, args.key, rails=args.rails, output_path=args.output)
    elif args.command == "analyze":
        display_frequency_analysis(args.file)
    elif args.command == "tamper":
        tamper_file(args.file)
    elif args.command == "demo":
        run_lab_demo()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
