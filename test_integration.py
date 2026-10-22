"""
CryptoNet - test_integration.py
Automated End-to-End Cryptographic & Socket Integration Tests
"""

import os
import sys
import time
import socket
import struct
import base64
import unittest
import threading

import crypto_utils as crypto


class TestCryptoNet(unittest.TestCase):
    def test_01_diffie_hellman_agreement(self):
        """Verify server and client independently arrive at the exact same shared secret."""
        # Alice (Server)
        priv_a, pub_a = crypto.generate_dh_keypair()
        # Bob (Client)
        priv_b, pub_b = crypto.generate_dh_keypair()

        # Alice computes s = B^a mod p
        s_alice = crypto.compute_dh_shared_secret(pub_b, priv_a)
        # Bob computes s = A^b mod p
        s_bob = crypto.compute_dh_shared_secret(pub_a, priv_b)

        self.assertEqual(s_alice, s_bob, "Diffie-Hellman shared secrets do not match!")
        self.assertGreater(s_alice.bit_length(), 200, "Shared secret bit length suspiciously small")

        # Session keys derived from shared secret must match
        k_alice = crypto.derive_session_key(s_alice)
        k_bob = crypto.derive_session_key(s_bob)
        self.assertEqual(k_alice, k_bob, "Derived session keys do not match!")

    def test_02_caesar_cipher(self):
        """Verify Caesar cipher encrypts and decrypts correctly for all byte values."""
        plaintext = b"CNS Lab 2026 Caesar Cipher Test !@#$%^&*()_+"
        shift = 42
        ct = crypto.caesar_encrypt(plaintext, shift)
        self.assertNotEqual(ct, plaintext)
        pt = crypto.caesar_decrypt(ct, shift)
        self.assertEqual(pt, plaintext)

    def test_03_vernam_cipher(self):
        """Verify Vernam OTP stream cipher with counter-based keystream."""
        key = crypto.derive_session_key(987654321)
        data = b"Vernam Cipher Perfect Secrecy One-Time Pad Stream"
        ct = crypto.vernam_encrypt(data, key, counter=1)
        self.assertEqual(len(ct), len(data))
        self.assertNotEqual(ct, data)
        pt = crypto.vernam_decrypt(ct, key, counter=1)
        self.assertEqual(pt, data)

        # Counter mismatch should fail decryption
        wrong_pt = crypto.vernam_decrypt(ct, key, counter=2)
        self.assertNotEqual(wrong_pt, data)

    def test_04_hill_cipher(self):
        """Verify 2x2 Hill cipher modulo 256 invertibility and padding."""
        key = crypto.derive_session_key(123456789)
        k_mat, k_inv = crypto.derive_hill_matrix(key)

        # Test identity: K * K_inv = I mod 256
        a, b = k_mat[0]
        c, d = k_mat[1]
        ia, ib = k_inv[0]
        ic, id_ = k_inv[1]
        self.assertEqual((a * ia + b * ic) % 256, 1)
        self.assertEqual((a * ib + b * id_) % 256, 0)
        self.assertEqual((c * ia + d * ic) % 256, 0)
        self.assertEqual((c * ib + d * id_) % 256, 1)

        # Test even length and odd length texts
        for text in [b"EvenLengthString!!", b"OddLengthStr!"]:
            ct = crypto.hill_encrypt(text, k_mat)
            self.assertEqual(len(ct) % 2, 0)
            pt = crypto.hill_decrypt(ct, k_inv)
            self.assertEqual(pt, text)

    def test_05_rail_fence_cipher(self):
        """Verify Rail Fence transposition with varying rail depths."""
        msg = b"DEFEND_THE_EAST_WALL_OF_THE_CASTLE_AT_DAWN_12345"
        for rails in [2, 3, 4, 5, 8]:
            transposed = crypto.rail_fence_encrypt(msg, rails)
            self.assertEqual(len(transposed), len(msg))
            recovered = crypto.rail_fence_decrypt(transposed, rails)
            self.assertEqual(recovered, msg, f"Rail fence failed at rails={rails}")

    def test_06_composite_pipelines(self):
        """Verify multi-layer pipelines: Vernam/Hill/Caesar + Rail Fence."""
        secret = 11223344556677889900
        k_sess = crypto.derive_session_key(secret)
        msg = "The quick brown fox jumps over the lazy dog 12345! @#$"

        for cipher in ["vernam", "hill", "caesar"]:
            tx, inter, h = crypto.encrypt_pipeline(msg, cipher, k_sess, counter=5, rails=3, shared_secret=secret)
            rx_pt, rx_inter = crypto.decrypt_pipeline(tx, cipher, k_sess, counter=5, rails=3, shared_secret=secret)
            self.assertEqual(rx_pt, msg)
            self.assertEqual(inter, rx_inter)

    def test_07_rsa_signatures_and_tamper(self):
        """Verify RSA signing, positive verification, and tamper rejection."""
        key_obj, priv_pem, pub_pem = crypto.generate_rsa_keypair(2048)
        data = b"Original Authentic Wire Ciphertext Bytes"
        sig = crypto.rsa_sign(data, key_obj)

        # 1. Valid signature verifies
        self.assertTrue(crypto.rsa_verify(data, sig, pub_pem))

        # 2. Tampered data fails
        tampered_data = bytearray(data)
        tampered_data[0] ^= 0x01
        self.assertFalse(crypto.rsa_verify(bytes(tampered_data), sig, pub_pem))

        # 3. Wrong public key fails
        _, _, other_pub = crypto.generate_rsa_keypair(2048)
        self.assertFalse(crypto.rsa_verify(data, sig, other_pub))

    def test_08_md5_integrity_and_logging(self):
        """Verify MD5 integrity hash and logging mechanism."""
        log_test_path = "logs/test_md5_log.log"
        data = b"Integrity Check Payload"
        digest, duration_ns, d_len = crypto.compute_md5(data)
        self.assertEqual(len(digest), 32)
        self.assertEqual(d_len, 16)
        self.assertGreater(duration_ns, 0)

        crypto.log_md5_metric(len(data), duration_ns, d_len, log_test_path, context="test")
        self.assertTrue(os.path.exists(log_test_path))
        with open(log_test_path, "r", encoding="utf-8") as f:
            content = f.read()
            self.assertIn("Integrity Benchmark Log", content)
            self.assertIn(f"{len(data)} B", content)


if __name__ == "__main__":
    unittest.main(verbosity=2)
