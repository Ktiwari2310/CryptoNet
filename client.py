"""
CryptoNet - client.py
TCP Socket Client with Diffie-Hellman Key Exchange, Multi-Layer Ciphers,
RSA Authentication, and MD5 Integrity Auditing.

CNS Lab Project: Connects to server.py to demonstrate secure chat and
cryptographic pipelines with transparent step-by-step CLI auditing.
"""

import os
import sys
import time
import socket
import struct
import base64
import argparse
import threading
from typing import Optional

# Ensure UTF-8 output on Windows console
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Import cryptographic primitives
import crypto_utils as crypto


class CryptoNetClient:
    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 9999,
        cipher_mode: str = "vernam",
        rails: int = 3,
        plain_mode: bool = False,
        log_file: str = "logs/hash_timing.log",
    ):
        self.host = host
        self.port = port
        self.cipher_mode = cipher_mode.lower()
        self.rails = rails
        self.plain_mode = plain_mode
        self.log_file = log_file

        self.running = False
        self.sock: Optional[socket.socket] = None

        # Cryptographic state
        self.dh_private_key: Optional[int] = None
        self.dh_public_key: Optional[int] = None
        self.dh_shared_secret: Optional[int] = None
        self.session_key: Optional[bytes] = None

        self.rsa_key = None
        self.rsa_priv_pem: Optional[bytes] = None
        self.rsa_pub_pem: Optional[bytes] = None
        self.peer_rsa_pub_pem: Optional[bytes] = None

        self.tx_counter = 0
        self.rx_counter = 0
        self.tamper_next = False

    def connect(self):
        """Connects to CryptoNet server and initiates security handshake."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            print("=" * 72)
            print("                 CRYPTONET SECURE CHAT CLIENT")
            print("=" * 72)
            print(f"[*] Connecting to server at {self.host}:{self.port} ...")
            self.sock.connect((self.host, self.port))
            self.running = True
            print(f"[+] Connected to server {self.host}:{self.port}")

            if not self.plain_mode:
                self._perform_handshake()
            else:
                print("[!] MODE: BASELINE PLAINTEXT (Unencrypted)")
                print("    All messages transmitted in cleartext for Wireshark inspection.\n")

            self._print_chat_banner()

            # Start background thread to listen for incoming messages
            rx_thread = threading.Thread(target=self._receive_loop, daemon=True)
            rx_thread.start()

            # Main thread handles user input and transmission
            self._send_loop()

        except ConnectionRefusedError:
            print(f"\n[!] Connection refused: Could not connect to {self.host}:{self.port}.")
            print("    Please ensure server.py is running first.")
        except KeyboardInterrupt:
            print("\n[*] Client disconnect requested by user.")
        except Exception as e:
            print(f"\n[!] Client error: {e}")
        finally:
            self.running = False
            if self.sock:
                try:
                    self.sock.close()
                except Exception:
                    pass
            print("[*] Client disconnected cleanly.")

    # ========================================================================
    # HANDSHAKE PHASE (DIFFIE-HELLMAN + RSA PUBLIC KEY EXCHANGE)
    # ========================================================================
    def _perform_handshake(self):
        """
        Executes mutual Diffie-Hellman Key Exchange and exchanges RSA Public Keys.
        1. Generate DH keypair and RSA-2048 keypair.
        2. Receive Server DH Public Key and RSA Public Key PEM.
        3. Send Client DH Public Key and RSA Public Key PEM.
        4. Independently compute DH Shared Secret: s = (Server_DH_Pub)^a mod p.
        5. Derive 256-bit symmetric session key: K = SHA-256(s).
        """
        print("\n" + "=" * 72)
        print("          PHASE 1: DIFFIE-HELLMAN & RSA SECURITY HANDSHAKE")
        print("=" * 72)

        # 1. Generate keys
        print("[*] Generating local RFC 3526 2048-bit Diffie-Hellman parameters...")
        self.dh_private_key, self.dh_public_key = crypto.generate_dh_keypair()
        print(f"    - Client DH Private Key (a): [CONFIDENTIAL - {self.dh_private_key.bit_length()} bits]")
        print(f"    - Client DH Public Key  (A): 0x{hex(self.dh_public_key)[2:34]}... (truncated)")

        print("[*] Generating local 2048-bit RSA authentication key pair...")
        self.rsa_key, self.rsa_priv_pem, self.rsa_pub_pem = crypto.generate_rsa_keypair(2048)
        print("    - RSA Public Key generated (PKCS#1 v1.5)")

        # 2. Receive server handshake packet first
        print("[*] Exchanging public credentials with server...")
        server_handshake = self._receive_raw_json()
        peer_dh_pub = int(server_handshake["dh_public_key"])
        self.peer_rsa_pub_pem = server_handshake["rsa_public_pem"].encode("ascii")

        print(f"    - Server DH Public Key  (B): 0x{hex(peer_dh_pub)[2:34]}... (truncated)")
        print("    - Server RSA Public Key received & cached for signature verification")

        # Send client handshake packet
        handshake_payload = {
            "dh_public_key": str(self.dh_public_key),
            "rsa_public_pem": self.rsa_pub_pem.decode("ascii"),
        }
        self._send_raw_json(handshake_payload)

        # 3. Compute DH Shared Secret
        print("[*] Computing independent Diffie-Hellman Shared Secret: s = B^a mod p ...")
        self.dh_shared_secret = crypto.compute_dh_shared_secret(peer_dh_pub, self.dh_private_key)
        secret_hex = hex(self.dh_shared_secret)[2:]
        print(f"[✓] DIFFIE-HELLMAN SHARED SECRET (s):")
        print(f"    0x{secret_hex[:40]}...{secret_hex[-20:]} ({self.dh_shared_secret.bit_length()} bits)")
        print("    [Notice: Compare this value with the server's output to verify exact match!]")

        # 4. Derive symmetric session key
        self.session_key = crypto.derive_session_key(self.dh_shared_secret)
        print(f"[✓] Derived 256-bit Symmetric Session Key: {self.session_key.hex()[:32]}... (SHA-256)")
        print("=" * 72 + "\n")

    # ========================================================================
    # TRANSMISSION / RECEPTION ENVELOPE (FRAMING)
    # ========================================================================
    def _send_raw_json(self, data_dict: dict):
        """Sends JSON packet with 4-byte length prefix."""
        import json
        payload = json.dumps(data_dict).encode("utf-8")
        header = struct.pack(">I", len(payload))
        self.sock.sendall(header + payload)

    def _receive_raw_json(self) -> dict:
        """Receives JSON packet with 4-byte length prefix."""
        import json
        header = self._recv_exact(4)
        if not header:
            raise ConnectionResetError("Connection closed while reading length prefix")
        length = struct.unpack(">I", header)[0]
        data = self._recv_exact(length)
        if not data:
            raise ConnectionResetError("Connection closed while reading payload")
        return json.loads(data.decode("utf-8"))

    def _recv_exact(self, num_bytes: int) -> Optional[bytes]:
        """Reads exactly num_bytes from the TCP socket."""
        buf = bytearray()
        while len(buf) < num_bytes:
            chunk = self.sock.recv(num_bytes - len(buf))
            if not chunk:
                return None
            buf.extend(chunk)
        return bytes(buf)

    # ========================================================================
    # CHAT LOOPS
    # ========================================================================
    def _print_chat_banner(self):
        print("=" * 72)
        print("Chat session is ACTIVE. Type your messages below.")
        print("Available Commands:")
        print("  /cipher <vernam|hill|caesar> : Switch primary encryption cipher")
        print("  /rails <int>                : Set Rail Fence transposition depth")
        print("  /tamper                     : Toggle simulated MITM payload tampering")
        print("  /bench                      : Run MD5 performance benchmarks")
        print("  /plain                      : Toggle unencrypted baseline mode")
        print("  /help                       : Show command menu")
        print("  /quit                       : Exit chat")
        print("=" * 72)

    def _send_loop(self):
        """Interactive loop reading user input and sending messages."""
        while self.running:
            try:
                line = input("\n[Client] > ").strip()
                if not line:
                    continue

                if line.startswith("/"):
                    self._handle_command(line)
                    continue

                if self.plain_mode:
                    self._send_plain_message(line)
                else:
                    self._send_secure_message(line)

            except (EOFError, KeyboardInterrupt):
                break
            except Exception as e:
                print(f"[!] Error transmitting message: {e}")
                break

    def _receive_loop(self):
        """Background thread receiving messages from server."""
        while self.running:
            try:
                if self.plain_mode:
                    header = self._recv_exact(4)
                    if not header:
                        print("\n[*] Server closed the connection.")
                        self.running = False
                        break
                    length = struct.unpack(">I", header)[0]
                    raw_data = self._recv_exact(length)
                    if not raw_data:
                        print("\n[*] Server closed the connection.")
                        self.running = False
                        break
                    plaintext = raw_data.decode("utf-8", errors="replace")
                    print(f"\n" + "-" * 60)
                    print(f"[RX - BASELINE PLAINTEXT] Received {len(raw_data)} bytes:")
                    print(f"Wire bytes: {raw_data!r}")
                    print(f"[Server]: {plaintext}")
                    print("-" * 60)
                    print("[Client] > ", end="", flush=True)

                else:
                    packet = self._receive_raw_json()
                    self._handle_secure_packet(packet)
                    print("[Client] > ", end="", flush=True)

            except (ConnectionResetError, ConnectionAbortedError):
                print("\n[*] Server closed the connection.")
                self.running = False
                break
            except Exception as e:
                if self.running:
                    print(f"\n[!] Receive loop error: {e}")
                self.running = False
                break

    # ========================================================================
    # MESSAGE TRANSMISSION PIPELINE
    # ========================================================================
    def _send_plain_message(self, plaintext: str):
        """Transmits raw unencrypted message for Wireshark inspection."""
        raw_bytes = plaintext.encode("utf-8")
        header = struct.pack(">I", len(raw_bytes))
        self.sock.sendall(header + raw_bytes)

        print("\n" + "=" * 70)
        print("[TX PIPELINE - BASELINE PLAINTEXT MODE]")
        print(f"1. Plaintext Message     : \"{plaintext}\" ({len(raw_bytes)} bytes)")
        print(f"2. Wire Bytes Transmitted: {raw_bytes!r}")
        print("   [Wireshark Filter: tcp.port == 9999 -> Follow TCP Stream to view cleartext]")
        print("=" * 70)

    def _send_secure_message(self, plaintext: str):
        """
        Executes the full cryptographic transmission pipeline:
        1. Plaintext MD5 integrity hashing & benchmark logging
        2. Primary Cipher (Vernam / Hill / Caesar)
        3. Transposition Cipher (Rail Fence)
        4. RSA-2048 Digital Signature over ciphertext
        5. Socket serialization
        """
        self.tx_counter += 1
        raw_bytes = plaintext.encode("utf-8")

        # Step 1: Plaintext MD5 Integrity Hash
        md5_digest, duration_ns, digest_len = crypto.compute_md5(raw_bytes)
        crypto.log_md5_metric(len(raw_bytes), duration_ns, digest_len, self.log_file, context="client_tx")

        # Step 2: Primary Cipher & Step 3: Rail Fence Transposition
        transposed_ct, intermediate_ct, _ = crypto.encrypt_pipeline(
            plaintext=plaintext,
            cipher_type=self.cipher_mode,
            session_key=self.session_key,
            counter=self.tx_counter,
            rails=self.rails,
            shared_secret=self.dh_shared_secret,
        )

        wire_ct = bytearray(transposed_ct)
        tamper_flag = False

        # Optional MITM Tamper Simulation
        if self.tamper_next:
            if len(wire_ct) > 0:
                wire_ct[0] ^= 0xFF  # Flip bits of first byte
            tamper_flag = True
            self.tamper_next = False
            print("\n[!] [SIMULATED MITM ATTACK]: Ciphertext byte #0 bitwise flipped before sending!")

        wire_ct_bytes = bytes(wire_ct)

        # Step 4: RSA Digital Signature
        signature = crypto.rsa_sign(wire_ct_bytes, self.rsa_key)

        # Step 5: Construct Wire Packet
        packet = {
            "type": "msg",
            "cipher": self.cipher_mode,
            "rails": self.rails,
            "counter": self.tx_counter,
            "ciphertext": base64.b64encode(wire_ct_bytes).decode("ascii"),
            "signature": base64.b64encode(signature).decode("ascii"),
            "md5": md5_digest,
            "tampered_sim": tamper_flag,
        }

        self._send_raw_json(packet)

        # CLI Step-by-Step Transparency
        print("\n" + "=" * 72)
        print("          [OUTGOING TRANSMISSION PIPELINE - CLIENT -> SERVER]")
        print("=" * 72)
        print(f"1. Plaintext Input      : \"{plaintext}\" ({len(raw_bytes)} bytes)")
        print(f"2. MD5 Integrity Digest : {md5_digest}")
        print(f"   - Hash Time / Size   : {duration_ns:.0f} ns ({duration_ns/1000:.2f} µs) | {digest_len*8} bits")
        print(f"3. Primary Cipher       : {self.cipher_mode.upper()}")
        print(f"   - Intermediate Hex   : {intermediate_ct.hex()[:48]}... ({len(intermediate_ct)} bytes)")
        print(f"4. Transposition Layer  : Rail Fence ({self.rails} rails)")
        print(f"   - Transposed Hex     : {wire_ct_bytes.hex()[:48]}... ({len(wire_ct_bytes)} bytes)")
        print(f"5. RSA-2048 Signature   : {signature.hex()[:48]}... ({len(signature)} bytes)")
        print(f"6. Wire JSON Envelope   : Encoded & transmitted with 4-byte length prefix")
        print("=" * 72)

    # ========================================================================
    # MESSAGE RECEPTION PIPELINE
    # ========================================================================
    def _handle_secure_packet(self, packet: dict):
        """
        Executes the full cryptographic reception pipeline:
        1. Parse JSON envelope
        2. RSA-2048 Signature verification against server's public key
        3. Reverse Rail Fence transposition
        4. Primary cipher decryption (Vernam / Hill / Caesar)
        5. Plaintext MD5 integrity verification
        """
        self.rx_counter += 1
        cipher = packet.get("cipher", self.cipher_mode)
        rails = packet.get("rails", self.rails)
        counter = packet.get("counter", self.rx_counter)
        wire_ct = base64.b64decode(packet["ciphertext"])
        signature = base64.b64decode(packet["signature"])
        received_md5 = packet["md5"]
        was_tampered = packet.get("tampered_sim", False)

        print("\n\n" + "=" * 72)
        print("          [INCOMING RECEPTION PIPELINE - SERVER -> CLIENT]")
        print("=" * 72)
        print(f"1. Wire Payload Received: {len(wire_ct)} ciphertext bytes + {len(signature)} signature bytes")

        # Step 2: RSA Signature Verification
        sig_valid = crypto.rsa_verify(wire_ct, signature, self.peer_rsa_pub_pem)
        if sig_valid:
            print("2. RSA-2048 Signature   : [VALID / VERIFIED ✓]")
            print("   - Non-repudiation and Server Identity Authenticated.")
        else:
            print("2. RSA-2048 Signature   : [INVALID / FAILED ✗] -> Tampering or Forgery Detected!")

        # Step 3 & 4: Reverse Rail Fence & Primary Decrypt
        try:
            recovered_plaintext, intermediate_ct = crypto.decrypt_pipeline(
                transposed_bytes=wire_ct,
                cipher_type=cipher,
                session_key=self.session_key,
                counter=counter,
                rails=rails,
                shared_secret=self.dh_shared_secret,
            )
            print(f"3. Rail Fence Reversal  : Transposition inverted ({rails} rails)")
            print(f"   - Intermediate Hex   : {intermediate_ct.hex()[:48]}...")
            print(f"4. Primary Decryption   : {cipher.upper()} -> Recovered \"{recovered_plaintext}\"")
        except Exception as e:
            recovered_plaintext = "<DECRYPTION FAILED>"
            print(f"3/4. Decryption Error   : {e}")

        # Step 5: MD5 Plaintext Integrity Check
        calc_md5, dur_ns, dig_len = crypto.compute_md5(recovered_plaintext.encode("utf-8"))
        crypto.log_md5_metric(len(recovered_plaintext.encode("utf-8")), dur_ns, dig_len, self.log_file, context="client_rx")

        print("5. Plaintext MD5 Check  :")
        print(f"   - Received Hash      : {received_md5}")
        print(f"   - Computed Hash      : {calc_md5}")
        if calc_md5 == received_md5 and not was_tampered:
            print("   - Integrity Status   : [MATCH ✓ - Message arrived authentic & intact]")
        else:
            print("   - Integrity Status   : [MISMATCH ✗ - TAMPERING DETECTED!]")

        print("=" * 72)
        print(f"[Server]: {recovered_plaintext}\n")

    # ========================================================================
    # INTERACTIVE COMMAND HANDLER
    # ========================================================================
    def _handle_command(self, cmd_line: str):
        parts = cmd_line.split()
        cmd = parts[0].lower()

        if cmd == "/help":
            self._print_chat_banner()

        elif cmd == "/cipher":
            if len(parts) < 2 or parts[1].lower() not in ["vernam", "hill", "caesar"]:
                print("[!] Usage: /cipher <vernam|hill|caesar>")
            else:
                self.cipher_mode = parts[1].lower()
                print(f"[*] Primary cipher mode set to: {self.cipher_mode.upper()}")

        elif cmd == "/rails":
            if len(parts) < 2 or not parts[1].isdigit() or int(parts[1]) < 2:
                print("[!] Usage: /rails <integer >= 2>")
            else:
                self.rails = int(parts[1])
                print(f"[*] Rail Fence rails set to: {self.rails}")

        elif cmd == "/tamper":
            self.tamper_next = not self.tamper_next
            state = "ENABLED (Next outgoing message ciphertext will be corrupted)" if self.tamper_next else "DISABLED"
            print(f"[*] MITM Tamper Simulation: {state}")

        elif cmd == "/bench":
            crypto.run_md5_benchmarks(self.log_file)

        elif cmd == "/plain":
            self.plain_mode = not self.plain_mode
            mode_str = "BASELINE PLAINTEXT (Unencrypted)" if self.plain_mode else "ENCRYPTED"
            print(f"[*] Mode switched to: {mode_str}")

        elif cmd in ["/quit", "/exit"]:
            print("[*] Terminating chat session...")
            self.running = False
            if self.sock:
                try:
                    self.sock.close()
                except Exception:
                    pass

        else:
            print(f"[!] Unknown command '{cmd}'. Type /help for available commands.")


def main():
    parser = argparse.ArgumentParser(
        description="CryptoNet - Secure Chat TCP Client for Cryptography & Network Security Lab"
    )
    parser.add_argument("--host", default="127.0.0.1", help="Server IP address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=9999, help="Server TCP Port (default: 9999)")
    parser.add_argument(
        "--cipher",
        choices=["vernam", "hill", "caesar"],
        default="vernam",
        help="Initial primary cipher (default: vernam)",
    )
    parser.add_argument("--rails", type=int, default=3, help="Rail fence transposition rails (default: 3)")
    parser.add_argument(
        "--plain",
        action="store_true",
        help="Run baseline unencrypted mode (for cleartext Wireshark inspection)",
    )
    parser.add_argument(
        "--benchmark",
        action="store_true",
        help="Run MD5 hashing benchmark and exit",
    )
    parser.add_argument(
        "--logfile",
        default="logs/hash_timing.log",
        help="Path to write MD5 timing and benchmark metrics",
    )

    args = parser.parse_args()

    if args.benchmark:
        crypto.run_md5_benchmarks(args.logfile)
        sys.exit(0)

    client = CryptoNetClient(
        host=args.host,
        port=args.port,
        cipher_mode=args.cipher,
        rails=args.rails,
        plain_mode=args.plain,
        log_file=args.logfile,
    )
    client.connect()


if __name__ == "__main__":
    main()
