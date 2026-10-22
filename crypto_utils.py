"""
CryptoNet - crypto_utils.py
Cryptographic and Network Security Utilities

This module implements all cryptographic algorithms required for the CryptoNet project:
1. Diffie-Hellman Key Exchange (RFC 3526 2048-bit MODP Group 14)
2. Caesar Cipher (classical substitution demonstration)
3. Vernam Cipher (One-Time Pad stream cipher using DH-derived keystream)
4. Hill Cipher (polygraphic substitution using 2x2 matrix modulo 256)
5. Rail Fence Cipher (transposition layer applied after primary encryption)
6. RSA Digital Signatures (PKCS#1 v1.5 with SHA-256 for non-repudiation and authentication)
7. MD5 Integrity Hashing & High-Precision Timing Benchmarks

Pure Python Standard Library + PyCryptodome only.
"""

import os
import sys
import time
import struct
import hashlib
import secrets
from typing import Tuple, List, Optional

# PyCryptodome imports for RSA authentication
try:
    from Crypto.PublicKey import RSA
    from Crypto.Signature import pkcs1_15
    from Crypto.Hash import SHA256
except ImportError:
    raise ImportError("pycryptodome is required. Install via: pip install pycryptodome")

# Configure UTF-8 stdout encoding for Windows console compatibility
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass


# ============================================================================
# 1. DIFFIE-HELLMAN KEY EXCHANGE (RFC 3526 - 2048-bit MODP Group 14)
# ============================================================================
# The prime p and generator g are publicly known standard parameters.
# Both parties independently generate a private key (a and b), compute public
# values (A = g^a mod p, B = g^b mod p), and exchange public values.
# Both then compute: s = B^a mod p = A^b mod p = g^(ab) mod p.
# An eavesdropper observing A and B cannot compute s due to the Discrete Logarithm Problem.

DH_PRIME_2048 = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16
)
DH_GENERATOR = 2


def generate_dh_keypair(p: int = DH_PRIME_2048, g: int = DH_GENERATOR) -> Tuple[int, int]:
    """
    Generates a Diffie-Hellman private and public key pair.
    Private key: random integer in [2, p - 2] (256-bit entropy).
    Public key: g^private_key mod p.
    """
    private_key = secrets.randbelow(p - 3) + 2
    public_key = pow(g, private_key, p)
    return private_key, public_key


def compute_dh_shared_secret(peer_public_key: int, my_private_key: int, p: int = DH_PRIME_2048) -> int:
    """
    Computes the DH shared secret: s = (peer_public_key)^(my_private_key) mod p.
    """
    if not (1 < peer_public_key < p - 1):
        raise ValueError("Invalid peer DH public key (out of range)")
    return pow(peer_public_key, my_private_key, p)


def derive_session_key(shared_secret: int, salt: bytes = b"CryptoNet-v1-Salt") -> bytes:
    """
    Derives a 256-bit symmetric session key from the shared secret integer using SHA-256.
    Key = SHA-256(salt || shared_secret_bytes)
    """
    secret_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, byteorder="big")
    return hashlib.sha256(salt + secret_bytes).digest()


# ============================================================================
# 2. CAESAR CIPHER (WEAK ENCRYPTION DEMONSTRATION)
# ============================================================================
# The Caesar cipher is a monoalphabetic substitution cipher where each byte or
# character is shifted by a fixed number of positions k.
# Encryption: C_i = (P_i + k) mod M
# Decryption: P_i = (C_i - k) mod M
# In CryptoNet, we support byte-level Caesar mod 256 to handle any character/binary data.

def caesar_encrypt(data: bytes, shift: int = 3) -> bytes:
    """
    Encrypts raw bytes using the Caesar shift cipher (modulo 256).
    """
    shift = shift % 256
    return bytes([(b + shift) % 256 for b in data])


def caesar_decrypt(data: bytes, shift: int = 3) -> bytes:
    """
    Decrypts raw bytes using the Caesar shift cipher (modulo 256).
    """
    shift = shift % 256
    return bytes([(b - shift) % 256 for b in data])


def derive_caesar_shift(shared_secret: int) -> int:
    """
    Derives a Caesar shift in range [1, 255] from the DH shared secret.
    """
    return (shared_secret % 255) + 1


# ============================================================================
# 3. VERNAM CIPHER (ONE-TIME PAD STREAM CIPHER)
# ============================================================================
# Gilbert Vernam's cipher (1917) XORs each bit/byte of plaintext with a keystream:
# C_i = P_i ^ K_i
# Decryption is identical:
# P_i = C_i ^ K_i
# In CryptoNet, a pseudorandom keystream is generated deterministically from the
# DH session key and a monotonic message counter using SHA-256 counter mode.

def generate_vernam_keystream(session_key: bytes, length: int, counter: int = 0) -> bytes:
    """
    Generates a deterministic pseudo-random keystream of the requested length
    from the session key and message counter using SHA-256 in counter mode.
    Keystream = Block_0 || Block_1 || ... where Block_j = SHA256(session_key || counter || j)
    """
    keystream = bytearray()
    block_index = 0
    while len(keystream) < length:
        h = hashlib.sha256()
        h.update(session_key)
        h.update(struct.pack(">Q", counter))
        h.update(struct.pack(">I", block_index))
        keystream.extend(h.digest())
        block_index += 1
    return bytes(keystream[:length])


def vernam_encrypt(data: bytes, session_key: bytes, counter: int = 0) -> bytes:
    """
    Encrypts data with Vernam cipher: C[i] = P[i] XOR Keystream[i]
    """
    keystream = generate_vernam_keystream(session_key, len(data), counter)
    return bytes([p ^ k for p, k in zip(data, keystream)])


def vernam_decrypt(data: bytes, session_key: bytes, counter: int = 0) -> bytes:
    """
    Decrypts data with Vernam cipher: P[i] = C[i] XOR Keystream[i]
    """
    # XOR encryption is symmetric; same operation decrypts
    return vernam_encrypt(data, session_key, counter)


# ============================================================================
# 4. HILL CIPHER (POLYGRAPHIC MATRIX SUBSTITUTION MODULO 256)
# ============================================================================
# Lester Hill's cipher (1929) encrypts blocks of m characters as linear combinations:
# C = K * P mod M
# P = K^(-1) * C mod M
# Here we implement a 2x2 matrix over Z_256 (the full byte domain):
# K = [[a, b], [c, d]]
# Det(K) = (ad - bc) mod 256
# K is invertible in Z_256 if and only if gcd(Det(K), 256) == 1 (Det(K) is odd).
# K^(-1) = Det(K)^(-1) * [[d, -b], [-c, a]] mod 256

def derive_hill_matrix(session_key: bytes) -> Tuple[List[List[int]], List[List[int]]]:
    """
    Derives an invertible 2x2 matrix K and its modular inverse K_inv modulo 256
    from the DH session key.
    """
    # Use first 4 bytes of session key as seed
    h = hashlib.sha256(session_key + b"HillKey").digest()
    a, b, c, d = h[0], h[1], h[2], h[3]

    # Ensure determinant is odd (coprime to 256)
    det = (a * d - b * c) % 256
    offset = 0
    while det % 2 == 0:
        offset += 1
        a = (a + 1) % 256
        det = (a * d - b * c) % 256

    # Modular inverse of determinant mod 256
    inv_det = pow(det, -1, 256)

    # Invertible 2x2 matrix mod 256:
    # K_inv = inv_det * [[d, -b], [-c, a]] mod 256
    k_matrix = [[a, b], [c, d]]
    k_inv = [
        [(d * inv_det) % 256, ((-b) * inv_det) % 256],
        [((-c) * inv_det) % 256, (a * inv_det) % 256]
    ]
    return k_matrix, k_inv


def hill_encrypt(data: bytes, key_matrix: List[List[int]]) -> bytes:
    """
    Encrypts bytes using 2x2 Hill cipher modulo 256.
    Pads odd-length data with PKCS#7 style single padding byte (0x01).
    """
    # 2-byte block alignment: pad with 1 byte if odd length
    padding_needed = (2 - (len(data) % 2)) % 2
    if padding_needed == 1:
        padded_data = data + b"\x01"
    else:
        padded_data = data + b"\x02\x02"  # standard 2-byte pad marker

    result = bytearray()
    a, b = key_matrix[0]
    c, d = key_matrix[1]

    for i in range(0, len(padded_data), 2):
        p1 = padded_data[i]
        p2 = padded_data[i + 1]
        c1 = (a * p1 + b * p2) % 256
        c2 = (c * p1 + d * p2) % 256
        result.append(c1)
        result.append(c2)

    return bytes(result)


def hill_decrypt(data: bytes, inv_matrix: List[List[int]]) -> bytes:
    """
    Decrypts bytes using 2x2 Hill cipher modular inverse matrix modulo 256.
    Removes the padding added during encryption.
    """
    if len(data) % 2 != 0:
        raise ValueError("Hill cipher ciphertext length must be a multiple of 2")

    result = bytearray()
    a, b = inv_matrix[0]
    c, d = inv_matrix[1]

    for i in range(0, len(data), 2):
        c1 = data[i]
        c2 = data[i + 1]
        p1 = (a * c1 + b * c2) % 256
        p2 = (c * c1 + d * c2) % 256
        result.append(p1)
        result.append(p2)

    # Remove padding
    decrypted = bytes(result)
    pad_val = decrypted[-1]
    if pad_val == 1:
        return decrypted[:-1]
    elif pad_val == 2 and len(decrypted) >= 2 and decrypted[-2] == 2:
        return decrypted[:-2]
    return decrypted


# ============================================================================
# 5. RAIL FENCE CIPHER (TRANSPOSITION CIPHER)
# ============================================================================
# Transposition cipher that writes characters along a zigzag wave on N rails
# and reads them row-by-row.
# In CryptoNet, it serves as the second layer in the composite encryption scheme:
# Plaintext -> [Vernam / Hill / Caesar] -> [Rail Fence Transposition] -> Wire bytes.

def rail_fence_encrypt(data: bytes, rails: int = 3) -> bytes:
    """
    Encrypts byte sequence using Rail Fence transposition with given number of rails.
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
    Reverses Rail Fence transposition and reconstructs the original byte sequence.
    """
    if rails <= 1 or len(data) <= rails:
        return data

    # Reconstruct rail sequence pattern
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

    # Count how many bytes fell into each rail
    counts = [pattern.count(r) for r in range(rails)]

    # Slice the ciphertext into the separate rows
    rows: List[List[int]] = []
    idx = 0
    for count in counts:
        rows.append(list(data[idx:idx + count]))
        idx += count

    # Read bytes following the original zigzag pattern
    result: List[int] = []
    pointers = [0] * rails
    for r in pattern:
        result.append(rows[r][pointers[r]])
        pointers[r] += 1

    return bytes(result)


# ============================================================================
# 6. RSA DIGITAL SIGNATURES (PKCS#1 v1.5 with SHA-256)
# ============================================================================
# Used for sender authentication and non-repudiation.
# Sender hashes the encrypted wire payload with SHA-256 and signs with sender's
# private key. Receiver verifies the signature with sender's public key.

def generate_rsa_keypair(key_size: int = 2048) -> Tuple[RSA.RsaKey, bytes, bytes]:
    """
    Generates a 2048-bit RSA key pair.
    Returns: (rsa_key_obj, private_pem, public_pem)
    """
    key = RSA.generate(key_size)
    private_pem = key.export_key()
    public_pem = key.publickey().export_key()
    return key, private_pem, public_pem


def rsa_sign(data: bytes, private_key: RSA.RsaKey) -> bytes:
    """
    Signs data using RSA private key and SHA-256 with PKCS#1 v1.5 padding.
    """
    digest = SHA256.new(data)
    signature = pkcs1_15.new(private_key).sign(digest)
    return signature


def rsa_verify(data: bytes, signature: bytes, public_key_pem: bytes) -> bool:
    """
    Verifies RSA PKCS#1 v1.5 signature against data's SHA-256 hash using public key PEM.
    Returns True if valid, False if tampered or invalid.
    """
    try:
        pub_key = RSA.import_key(public_key_pem)
        digest = SHA256.new(data)
        pkcs1_15.new(pub_key).verify(digest, signature)
        return True
    except (ValueError, TypeError):
        return False


# ============================================================================
# 7. MD5 INTEGRITY CHECK & HIGH-PRECISION TIMING BENCHMARK
# ============================================================================
# Plaintext integrity: compute MD5 hash of plaintext before transmission.
# Receiver recomputes MD5 of decrypted plaintext to verify integrity.
# Generation time and digest size are logged to logs/hash_timing.log.

def compute_md5(data: bytes) -> Tuple[str, float, int]:
    """
    Computes MD5 hash of data and measures execution duration in nanoseconds.
    Returns: (hex_digest, duration_ns, digest_size_bytes)
    """
    start_ns = time.perf_counter_ns()
    digest = hashlib.md5(data).hexdigest()
    end_ns = time.perf_counter_ns()
    duration_ns = float(end_ns - start_ns)
    digest_size_bytes = 16  # MD5 is always 128-bit / 16 bytes
    return digest, duration_ns, digest_size_bytes


def log_md5_metric(message_size: int, duration_ns: float, digest_size: int, log_path: str, context: str = "chat"):
    """
    Appends MD5 benchmark / timing metrics to the designated log file.
    """
    os.makedirs(os.path.dirname(os.path.abspath(log_path)), exist_ok=True)
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    duration_us = duration_ns / 1000.0
    duration_ms = duration_ns / 1_000_000.0

    header_needed = not os.path.exists(log_path) or os.path.getsize(log_path) == 0

    with open(log_path, "a", encoding="utf-8") as f:
        if header_needed:
            f.write("=" * 90 + "\n")
            f.write(f"CryptoNet MD5 Hashing Performance & Integrity Benchmark Log\n")
            f.write(f"Columns: Timestamp | Context | Size (Bytes) | Digest Size (Bits) | Time (ns) | Time (us) | Time (ms)\n")
            f.write("=" * 90 + "\n")
        f.write(f"[{timestamp}] | {context:<12} | {message_size:>10} B | {digest_size * 8:>3} bits ({digest_size}B) | {duration_ns:>10.0f} ns | {duration_us:>8.2f} us | {duration_ms:>8.4f} ms\n")


def run_md5_benchmarks(log_path: str = "logs/hash_timing.log") -> None:
    """
    Runs an automated benchmark across varying message sizes to produce
    comprehensive timing data for lab reports.
    """
    print("\n" + "=" * 70)
    print("CryptoNet MD5 Hashing Benchmark - Varying Payload Sizes")
    print("=" * 70)
    sizes = [
        16,          # 16 Bytes (short token/command)
        64,          # 64 Bytes (typical short chat message)
        256,         # 256 Bytes (medium paragraph)
        1024,        # 1 KB (small text file / document)
        4096,        # 4 KB (standard memory page)
        16384,       # 16 KB (medium payload)
        65536,       # 64 KB (large TCP window size)
        262144,      # 256 KB
        1048576,     # 1 MB (large file transfer)
    ]

    print(f"{'Size (Bytes)':<14} | {'Digest Size':<14} | {'Avg Time (ns)':<16} | {'Avg Time (us)':<14} | {'Throughput (MB/s)':<18}")
    print("-" * 80)

    for sz in sizes:
        sample_data = os.urandom(sz)
        iterations = 100 if sz < 1048576 else 20
        total_time_ns = 0.0

        for _ in range(iterations):
            _, duration_ns, digest_len = compute_md5(sample_data)
            total_time_ns += duration_ns

        avg_ns = total_time_ns / iterations
        avg_us = avg_ns / 1000.0
        throughput_mb_s = (sz / (avg_ns / 1e9)) / (1024 * 1024) if avg_ns > 0 else 0.0

        print(f"{sz:<14} | {digest_len * 8} bits (16B)  | {avg_ns:<16.1f} | {avg_us:<14.2f} | {throughput_mb_s:<18.2f}")
        log_md5_metric(sz, avg_ns, digest_len, log_path, context="benchmark")

    print("-" * 80)
    print(f"Benchmark results successfully logged to: {log_path}\n")


# ============================================================================
# COMPOSITE ENCRYPTION PIPELINE
# ============================================================================

def encrypt_pipeline(
    plaintext: str,
    cipher_type: str,
    session_key: bytes,
    counter: int = 0,
    rails: int = 3,
    shared_secret: Optional[int] = None
) -> Tuple[bytes, bytes, str]:
    """
    Executes the multi-stage encryption pipeline:
    1. Plaintext UTF-8 bytes
    2. Primary Cipher: Vernam, Hill, or Caesar
    3. Transposition Cipher: Rail Fence
    Returns: (transposed_ciphertext, intermediate_ciphertext, md5_digest)
    """
    raw_bytes = plaintext.encode("utf-8")

    # Step 1: Compute MD5 of plaintext for integrity check
    md5_digest, duration_ns, digest_len = compute_md5(raw_bytes)

    # Step 2: Primary Cipher
    cipher_type = cipher_type.lower()
    if cipher_type == "vernam":
        intermediate = vernam_encrypt(raw_bytes, session_key, counter)
    elif cipher_type == "hill":
        k_matrix, _ = derive_hill_matrix(session_key)
        intermediate = hill_encrypt(raw_bytes, k_matrix)
    elif cipher_type == "caesar":
        shift = derive_caesar_shift(shared_secret if shared_secret else int.from_bytes(session_key[:4], "big"))
        intermediate = caesar_encrypt(raw_bytes, shift)
    else:
        raise ValueError(f"Unknown cipher type: {cipher_type}")

    # Step 3: Rail Fence Transposition
    transposed = rail_fence_encrypt(intermediate, rails)

    return transposed, intermediate, md5_digest


def decrypt_pipeline(
    transposed_bytes: bytes,
    cipher_type: str,
    session_key: bytes,
    counter: int = 0,
    rails: int = 3,
    shared_secret: Optional[int] = None
) -> Tuple[str, bytes]:
    """
    Reverses the multi-stage encryption pipeline:
    1. Reverses Rail Fence Transposition -> Intermediate Ciphertext
    2. Primary Decryption: Vernam, Hill, or Caesar -> Recovered Plaintext
    Returns: (decrypted_plaintext_str, intermediate_ciphertext)
    """
    # Step 1: Undo Rail Fence Transposition
    intermediate = rail_fence_decrypt(transposed_bytes, rails)

    # Step 2: Primary Decryption
    cipher_type = cipher_type.lower()
    if cipher_type == "vernam":
        recovered_bytes = vernam_decrypt(intermediate, session_key, counter)
    elif cipher_type == "hill":
        _, k_inv = derive_hill_matrix(session_key)
        recovered_bytes = hill_decrypt(intermediate, k_inv)
    elif cipher_type == "caesar":
        shift = derive_caesar_shift(shared_secret if shared_secret else int.from_bytes(session_key[:4], "big"))
        recovered_bytes = caesar_decrypt(intermediate, shift)
    else:
        raise ValueError(f"Unknown cipher type: {cipher_type}")

    plaintext = recovered_bytes.decode("utf-8", errors="replace")
    return plaintext, intermediate


if __name__ == "__main__":
    # If run standalone, execute benchmarks and unit self-tests
    print("Running crypto_utils standalone test suite...")
    test_secret = 1234567890987654321
    k_sess = derive_session_key(test_secret)

    test_msg = "Hello, Cryptography & Network Security Lab! 🚀"
    print(f"\nOriginal message: {test_msg}")

    for mode in ["vernam", "hill", "caesar"]:
        tx, inter, h = encrypt_pipeline(test_msg, mode, k_sess, counter=1, rails=3, shared_secret=test_secret)
        rx_plain, rx_inter = decrypt_pipeline(tx, mode, k_sess, counter=1, rails=3, shared_secret=test_secret)
        assert rx_plain == test_msg, f"Decryption failed for {mode}"
        assert inter == rx_inter, f"Intermediate mismatch for {mode}"
        h_rec, _, _ = compute_md5(rx_plain.encode("utf-8"))
        assert h == h_rec, f"MD5 mismatch for {mode}"
        print(f"[{mode.upper()} + Rail Fence 3]: PASS (Intermediate: {inter.hex()[:24]}..., Final: {tx.hex()[:24]}...)")

    # RSA test
    rsa_key, priv, pub = generate_rsa_keypair(2048)
    sig = rsa_sign(b"Test wire payload", rsa_key)
    assert rsa_verify(b"Test wire payload", sig, pub) is True
    assert rsa_verify(b"Tampered payload", sig, pub) is False
    print("[RSA-2048 PKCS#1 v1.5 Sign & Verify]: PASS")

    # Benchmarks
    run_md5_benchmarks("logs/hash_timing.log")
    print("All crypto_utils self-tests passed successfully!")
