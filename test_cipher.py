"""
test_cipher.py
Automated Unit Tests for Text File Encrypter/Decrypter CLI Tool
"""

import os
import unittest
import filecipher


class TestTextFileCipher(unittest.TestCase):
    def setUp(self):
        self.test_text = "Cryptography & Network Security Lab 2026 - Text File Encryption Demonstration!".encode("utf-8")
        self.temp_file = "test_plain.txt"
        with open(self.temp_file, "wb") as f:
            f.write(self.test_text)

    def tearDown(self):
        for fname in [self.temp_file, f"{self.temp_file}.enc", f"{self.temp_file}.hash", f"{self.temp_file}.decrypted", "test.key"]:
            if os.path.exists(fname):
                try:
                    os.remove(fname)
                except Exception:
                    pass

    def test_01_custom_keygen(self):
        """Test custom random One-Time Pad key generation."""
        key_len = 128
        key = filecipher.generate_custom_otp_key(key_len, "test.key")
        self.assertEqual(len(key), key_len)
        self.assertTrue(os.path.exists("test.key"))

    def test_02_vernam_xor_invertibility(self):
        """Test Gilbert Vernam's XOR stream cipher reversibility."""
        key = filecipher.generate_custom_otp_key(len(self.test_text), "test.key")
        ciphertext = filecipher.vernam_xor(self.test_text, key)
        self.assertNotEqual(ciphertext, self.test_text)
        recovered = filecipher.vernam_xor(ciphertext, key)
        self.assertEqual(recovered, self.test_text)

    def test_03_rail_fence_transposition(self):
        """Test Rail Fence transposition across multiple rail configurations."""
        for rails in [2, 3, 4, 5]:
            transposed = filecipher.rail_fence_encrypt(self.test_text, rails=rails)
            self.assertEqual(len(transposed), len(self.test_text))
            recovered = filecipher.rail_fence_decrypt(transposed, rails=rails)
            self.assertEqual(recovered, self.test_text)

    def test_04_hybrid_pipeline_with_keyfile(self):
        """Test full encryption and decryption pipeline with custom keyfile."""
        filecipher.generate_custom_otp_key(len(self.test_text), "test.key")
        filecipher.encrypt_file(self.temp_file, "test.key", rails=3)
        self.assertTrue(os.path.exists(f"{self.temp_file}.enc"))
        self.assertTrue(os.path.exists(f"{self.temp_file}.hash"))

        filecipher.decrypt_file(f"{self.temp_file}.enc", "test.key", rails=3)
        self.assertTrue(os.path.exists(f"{self.temp_file}.decrypted"))
        with open(f"{self.temp_file}.decrypted", "rb") as f:
            decrypted = f.read()
        self.assertEqual(decrypted, self.test_text)

    def test_05_hybrid_pipeline_with_password(self):
        """Test full encryption and decryption pipeline with password-derived key."""
        password = "LabSecretPassword2026!"
        filecipher.encrypt_file(self.temp_file, password, rails=4)
        filecipher.decrypt_file(f"{self.temp_file}.enc", password, rails=4)

        with open(f"{self.temp_file}.decrypted", "rb") as f:
            decrypted = f.read()
        self.assertEqual(decrypted, self.test_text)

    def test_06_tamper_detection(self):
        """Test that ciphertext tampering is detected by the integrity verification."""
        filecipher.generate_custom_otp_key(len(self.test_text), "test.key")
        filecipher.encrypt_file(self.temp_file, "test.key", rails=3)

        # Tamper with encrypted file
        filecipher.tamper_file(f"{self.temp_file}.enc")

        # Decrypt tampered file
        filecipher.decrypt_file(f"{self.temp_file}.enc", "test.key", rails=3)
        with open(f"{self.temp_file}.decrypted", "rb") as f:
            tampered_decrypted = f.read()
        # Plaintext must NOT match original due to tampering
        self.assertNotEqual(tampered_decrypted, self.test_text)

    def test_07_shannon_entropy(self):
        """Test that ciphertext entropy is significantly higher than plaintext entropy."""
        key = filecipher.generate_custom_otp_key(len(self.test_text), "test.key")
        ciphertext = filecipher.rail_fence_encrypt(filecipher.vernam_xor(self.test_text, key), 3)

        pt_entropy = filecipher.calculate_shannon_entropy(self.test_text)
        ct_entropy = filecipher.calculate_shannon_entropy(ciphertext)

        self.assertGreater(ct_entropy, pt_entropy)
        self.assertGreater(ct_entropy, 5.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
