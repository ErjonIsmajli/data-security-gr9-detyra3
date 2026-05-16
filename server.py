"""
SSH Handshake Server - Simplified Implementation
Simulates the server-side of an SSH protocol handshake.
Author: SSH Handshake Project
"""

import socket
import json
import os
import logging
import hashlib
import hmac
import time
from cryptography.hazmat.primitives.asymmetric import dh, padding, rsa
from cryptography.hazmat.primitives.asymmetric.dh import DHParameterNumbers, DHPublicNumbers, DHPrivateNumbers
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# ─────────────────────────────────────────────
# Logging Configuration
# ─────────────────────────────────────────────
import sys

class FlushStreamHandler(logging.StreamHandler):
    """StreamHandler that flushes after every record so logs appear immediately in terminal."""
    def emit(self, record):
        super().emit(record)
        self.flush()

# Always write server.log next to server.py, regardless of where you run from
_log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "server.log")

_fmt = logging.Formatter("[%(asctime)s] [SERVER] %(levelname)s: %(message)s")
_file_handler = logging.FileHandler(_log_path, mode="a", encoding="utf-8")
_file_handler.setFormatter(_fmt)
_console_handler = FlushStreamHandler(sys.stdout)
_console_handler.setFormatter(_fmt)

logging.root.setLevel(logging.INFO)
logging.root.handlers = []  # clear any pre-existing handlers before adding ours
logging.root.addHandler(_file_handler)
logging.root.addHandler(_console_handler)
log = logging.getLogger(__name__)

# ─────────────────────────────────────────────
# Server Configuration
# ─────────────────────────────────────────────
HOST = "127.0.0.1"
PORT = 2222

# Supported algorithms (sent during negotiation phase)
SUPPORTED_ALGOS = {
    "kex": ["diffie-hellman-group14-sha256"],
    "encryption": ["aes256-cbc"],
    "mac": ["hmac-sha256"],
    "compression": ["none"]
}

# ─────────────────────────────────────────────
# Helper: Send and Receive JSON messages
# ─────────────────────────────────────────────

def send_msg(conn: socket.socket, data: dict) -> None:
    """Serialize and send a JSON message, prefixed with 4-byte length."""
    raw = json.dumps(data).encode()
    length = len(raw).to_bytes(4, "big")
    conn.sendall(length + raw)


def recv_msg(conn: socket.socket) -> dict:
    """Read a length-prefixed JSON message from the socket."""
    raw_len = _recv_exact(conn, 4)
    length = int.from_bytes(raw_len, "big")
    raw = _recv_exact(conn, length)
    return json.loads(raw.decode())


def _recv_exact(conn: socket.socket, n: int) -> bytes:
    """Read exactly n bytes from a socket."""
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed by peer")
        buf += chunk
    return buf


# ─────────────────────────────────────────────
# RSA Key Generation / Management
# ─────────────────────────────────────────────

def generate_rsa_host_key():
    """Generate an RSA key pair to act as the server's host key."""
    log.info("Generating RSA host key pair (2048-bit)...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return private_key


def get_public_key_bytes(private_key) -> bytes:
    """Serialize the public key to PEM format for transmission."""
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


# ─────────────────────────────────────────────
# Diffie-Hellman Key Exchange
# ─────────────────────────────────────────────

def generate_dh_parameters():
    """
    Use well-known DH Group 14 parameters (RFC 3526).
    p is a 2048-bit prime, g=2 is the generator.
    """
    log.info("Loading DH Group 14 parameters (RFC 3526)...")
    # Standard DH Group 14 prime (2048-bit)
    p = int(
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
        "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
        16
    )
    g = 2
    return p, g


def dh_generate_server_keypair(p: int, g: int):
    """Generate server's DH private/public key pair using group14 params."""
    pn = DHParameterNumbers(p, g)
    params = pn.parameters(default_backend())
    server_private = params.generate_private_key()
    server_pub_int = server_private.public_key().public_numbers().y
    return server_private, server_pub_int


def dh_compute_shared_secret(server_private, client_pub_int: int, p: int, g: int) -> bytes:
    """Compute the DH shared secret using the client's public key."""
    pn = DHParameterNumbers(p, g)
    pub_numbers = DHPublicNumbers(client_pub_int, pn)
    client_pub_key = pub_numbers.public_key(default_backend())
    shared_secret = server_private.exchange(client_pub_key)
    return shared_secret


# ─────────────────────────────────────────────
# Session Key Derivation
# ─────────────────────────────────────────────

def derive_session_keys(shared_secret: bytes, client_nonce: bytes, server_nonce: bytes) -> dict:
    """
    Derive session keys for encryption and MAC from the shared secret.
    Uses HKDF-style derivation with SHA-256.
    Keys are derived by hashing the shared secret with nonces and labels.
    """

    def derive(label: str, length: int) -> bytes:
        h = hashlib.sha256(shared_secret + client_nonce + server_nonce + label.encode()).digest()
        # Extend if needed (for larger keys, repeat hashing)
        while len(h) < length:
            h += hashlib.sha256(h + shared_secret + label.encode()).digest()
        return h[:length]

    keys = {
        "encryption_key": derive("encryption_key", 32),  # 256-bit AES key
        "mac_key": derive("mac_key", 32),                 # 256-bit HMAC key
        "iv": derive("iv", 16),                           # 128-bit IV for AES-CBC
    }
    return keys


# ─────────────────────────────────────────────
# Digital Signature
# ─────────────────────────────────────────────

def sign_exchange_hash(host_private_key, exchange_hash: bytes) -> bytes:
    """Sign the exchange hash with the server's RSA private key."""
    signature = host_private_key.sign(
        exchange_hash,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return signature


def compute_exchange_hash(client_nonce: bytes, server_nonce: bytes,
                           client_pub_int: int, server_pub_int: int,
                           shared_secret: bytes) -> bytes:
    """Compute the exchange hash H used for server authentication."""
    data = (
        client_nonce +
        server_nonce +
        client_pub_int.to_bytes(256, "big") +
        server_pub_int.to_bytes(256, "big") +
        shared_secret
    )
    return hashlib.sha256(data).digest()

# ─────────────────────────────────────────────
# Handshake Handler
# ─────────────────────────────────────────────

def handle_handshake(conn: socket.socket, addr, host_private_key, dh_params):
    """
    Perform all SSH handshake phases with a connected client.

    Phases:
      1. Protocol version exchange
      2. Algorithm negotiation (KEXINIT)
      3. DH key exchange (KEX)
      4. Server authentication (host key + signature)
      5. Session key derivation
      6. NEWKEYS confirmation
    """
    session_start = time.time()
    log.info(f"{'='*60}")
    log.info(f"NEW CONNECTION from {addr[0]}:{addr[1]}")
    log.info(f"{'='*60}")
    print("\n" + "="*55)
    print("  Client connected! Initiating handshake...")
    print("="*55)

    try:
        # ── Phase 1: Protocol Version Exchange ──────────────
        log.info("[Phase 1] >>> Starting: Protocol Version Exchange")
        print("\n[Phase 1] Protocol version exchange...")

        server_version = {"type": "SSH_VERSION", "version": "SSH-2.0-SimplSSH_1.0"}
        send_msg(conn, server_version)
        log.info(f"[Phase 1] --> Sent server version: {server_version['version']}")

        client_version = recv_msg(conn)
        if client_version.get("type") != "SSH_VERSION":
            raise ValueError("Expected SSH_VERSION from client")
        log.info(f"[Phase 1] <-- Received client version: {client_version['version']}")
        print(f"  ✔ Client version: {client_version['version']}")

        # ── Phase 2: Algorithm Negotiation (KEXINIT) ────────
        log.info("[Phase 2] >>> Starting: Algorithm Negotiation (KEXINIT)")
        print("\n[Phase 2] Algorithm negotiation...")

        server_kexinit = {"type": "KEXINIT", "algorithms": SUPPORTED_ALGOS}
        send_msg(conn, server_kexinit)
        log.info(f"[Phase 2] --> Sent server algorithm proposals: {SUPPORTED_ALGOS}")

        client_kexinit = recv_msg(conn)
        if client_kexinit.get("type") != "KEXINIT":
            raise ValueError("Expected KEXINIT from client")
        client_algos = client_kexinit["algorithms"]
        log.info(f"[Phase 2] <-- Received client algorithm proposals: {client_algos}")
         # Intersect to find agreed algorithms
        agreed_kex = list(set(SUPPORTED_ALGOS["kex"]) & set(client_algos["kex"]))[0]
        agreed_enc = list(set(SUPPORTED_ALGOS["encryption"]) & set(client_algos["encryption"]))[0]
        agreed_mac = list(set(SUPPORTED_ALGOS["mac"]) & set(client_algos["mac"]))[0]
        log.info(f"[Phase 2] ✔ Agreed algorithms — kex: {agreed_kex} | cipher: {agreed_enc} | mac: {agreed_mac}")
        print(f"  ✔ Agreed kex      : {agreed_kex}")
        print(f"  ✔ Agreed cipher   : {agreed_enc}")
        print(f"  ✔ Agreed MAC      : {agreed_mac}")

        # ── Phase 3: DH Key Exchange ────────────────────────
        log.info("[Phase 3] >>> Starting: Diffie-Hellman Key Exchange")
        print("\n[Phase 3] Diffie-Hellman key exchange...")

        p, g = dh_params
        server_private, server_pub_int = dh_generate_server_keypair(p, g)
        log.info(f"[Phase 3] Server DH public key (first 32 hex chars): {hex(server_pub_int)[:32]}...")

        # Receive client's DH public value and nonce
        kex_init = recv_msg(conn)
        if kex_init.get("type") != "KEX_INIT":
            raise ValueError("Expected KEX_INIT from client")
        client_pub_int = int(kex_init["dh_public"])
        client_nonce = bytes.fromhex(kex_init["nonce"])
        log.info(f"[Phase 3] <-- Received client DH public key (first 32 hex chars): {hex(client_pub_int)[:32]}...")
        log.info(f"[Phase 3] <-- Received client nonce: {client_nonce.hex()[:16]}... ({len(client_nonce)} bytes)")
        log.info(f"[Phase 3] Client DH key bit-length: {client_pub_int.bit_length()} bits")
        print("  ✔ Received client DH public key and nonce")

  # Generate server nonce
        server_nonce = os.urandom(32)
        log.info(f"[Phase 3] Generated server nonce: {server_nonce.hex()[:16]}... ({len(server_nonce)} bytes)")

        # Send server's DH public value, nonce, and host public key
        host_pub_bytes = get_public_key_bytes(host_private_key)
        send_msg(conn, {
            "type": "KEX_REPLY",
            "dh_public": str(server_pub_int),
            "nonce": server_nonce.hex(),
            "host_public_key": host_pub_bytes.decode()
        })
        log.info(f"[Phase 3] --> Sent server DH public key, nonce, and RSA host public key ({len(host_pub_bytes)} bytes)")
        print("  ✔ Sent server DH public key and host key to client")

        # ── Phase 4: Compute Shared Secret & Sign ───────────
        log.info("[Phase 4] >>> Starting: Server Authentication (Digital Signature)")
        print("\n[Phase 4] Server authentication (digital signature)...")

        shared_secret = dh_compute_shared_secret(server_private, client_pub_int, p, g)
        log.info(f"[Phase 4] Shared secret computed ({len(shared_secret)} bytes): {shared_secret.hex()[:16]}...")

        exchange_hash = compute_exchange_hash(
            client_nonce, server_nonce,
            client_pub_int, server_pub_int,
            shared_secret
        )
        log.info(f"[Phase 4] Exchange hash (SHA-256): {exchange_hash.hex()}")

        signature = sign_exchange_hash(host_private_key, exchange_hash)
        log.info(f"[Phase 4] RSA signature ({len(signature)} bytes): {signature.hex()[:32]}...")

        # Send signature to client for server authentication
        send_msg(conn, {
            "type": "HOST_SIGNATURE",
            "signature": signature.hex(),
            "exchange_hash": exchange_hash.hex()
        })
        log.info(f"[Phase 4] --> Sent HOST_SIGNATURE to client for verification")
        print("  ✔ Signed exchange hash and sent signature to client")

        # ── Phase 5: Session Key Derivation ─────────────────
        log.info("[Phase 5] >>> Starting: Session Key Derivation")
        print("\n[Phase 5] Deriving session keys...")

        session_keys = derive_session_keys(shared_secret, client_nonce, server_nonce)
        log.info(f"[Phase 5] encryption_key: {session_keys['encryption_key'].hex()[:16]}... (32 bytes, AES-256)")
        log.info(f"[Phase 5] mac_key:        {session_keys['mac_key'].hex()[:16]}... (32 bytes, HMAC-SHA256)")
        log.info(f"[Phase 5] iv:             {session_keys['iv'].hex()} (16 bytes, AES-CBC IV)")
        log.info(f"[Phase 5] ✔ All session keys derived successfully")
        print("  ✔ Session keys derived (AES-256 + HMAC-SHA256)")

        # ── Phase 6: NEWKEYS – Confirm handshake complete ───
        log.info("[Phase 6] >>> Starting: NEWKEYS Confirmation")
        print("\n[Phase 6] NEWKEYS confirmation...")

        client_newkeys = recv_msg(conn)
        if client_newkeys.get("type") != "NEWKEYS":
            raise ValueError("Expected NEWKEYS from client")
        log.info(f"[Phase 6] <-- Received NEWKEYS from client")
        print("  ✔ Received NEWKEYS from client")

        send_msg(conn, {"type": "NEWKEYS"})
        log.info(f"[Phase 6] --> Sent NEWKEYS to client")
        log.info(f"[Phase 6] ✔ Both sides confirmed key switch")
        print("  ✔ Sent NEWKEYS to client")

        # ── Success ─────────────────────────────────────────
        elapsed = round(time.time() - session_start, 3)
        print("\n" + "="*55)
        print("  ✅ Handshake successful! Secure channel established.")
        print("="*55 + "\n")
        log.info(f"{'='*60}")
        log.info(f"[SUCCESS] Handshake complete in {elapsed}s — secure channel established with {addr[0]}:{addr[1]}")
        log.info(f"{'='*60}")

        send_msg(conn, {
            "type": "HANDSHAKE_COMPLETE",
            "message": "Secure channel established. Session is active."
        })

    except Exception as e:
        elapsed = round(time.time() - session_start, 3)
        log.error(f"{'='*60}")
        log.error(f"[FAILURE] Handshake failed after {elapsed}s — {type(e).__name__}: {e}")
        log.error(f"{'='*60}")
        print(f"\n  ❌ Handshake failed: {e}")
        try:
            send_msg(conn, {"type": "ERROR", "message": str(e)})
        except Exception:
            pass
    finally:
        conn.close()
        log.info(f"Connection with {addr[0]}:{addr[1]} closed.")


# ─────────────────────────────────────────────
# Main Entry Point
# ─────────────────────────────────────────────

def main():
    print("\n" + "="*55)
    print("   Simplified SSH Server - Starting Up")
    print("="*55)

    host_private_key = generate_rsa_host_key()

    print("  Pre-generating DH parameters (one-time)...")
    dh_params = generate_dh_parameters()
    print("  DH parameters ready.\n")

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((HOST, PORT))
    server_sock.listen(5)

    print(f"\n  Server listening on {HOST}:{PORT}")
    print("  Awaiting client connections...\n")
    log.info(f"Server listening on {HOST}:{PORT}")

    while True:
        try:
            conn, addr = server_sock.accept()
            handle_handshake(conn, addr, host_private_key, dh_params)
        except KeyboardInterrupt:
            print("\n\n  Server shutting down...")
            log.info("Server stopped by user.")
            break
        except Exception as e:
            log.error(f"Unexpected error: {e}")

    server_sock.close()


if __name__ == "__main__":
    main()

      


       
