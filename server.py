"""
SSH Handshake Server - Simplified Implementation
Simulates the server-side of an SSH protocol handshake.
"""

import os
import sys
import socket
import json
import logging
import hashlib
import hmac
import time

# Force unbuffered output — every print() appears immediately on Windows
os.environ["PYTHONUNBUFFERED"] = "1"

from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.dh import DHParameterNumbers, DHPublicNumbers
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# ─────────────────────────────────────────────
# Logging — flush after every line
# ─────────────────────────────────────────────

class FlushHandler(logging.StreamHandler):
    """Writes to stderr — stderr is never buffered on Windows, unlike stdout."""
    def emit(self, record):
        try:
            msg = self.format(record)
            sys.stderr.write(msg + "\n")
            sys.stderr.flush()
        except Exception:
            self.handleError(record)

_log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "server.log")
_fmt = logging.Formatter("[%(asctime)s] [SERVER] %(levelname)s: %(message)s")
_fh = logging.FileHandler(_log_path, mode="a", encoding="utf-8")
_fh.setFormatter(_fmt)
_ch = FlushHandler()
_ch.setFormatter(_fmt)
logging.root.setLevel(logging.INFO)
logging.root.handlers = []
logging.root.addHandler(_fh)
logging.root.addHandler(_ch)
log = logging.getLogger(__name__)

# ─────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────
HOST = "127.0.0.1"
PORT = 2222

SUPPORTED_ALGOS = {
    "kex": ["diffie-hellman-group14-sha256"],
    "encryption": ["aes256-cbc"],
    "mac": ["hmac-sha256"],
    "compression": ["none"]
}

# ─────────────────────────────────────────────
# Messaging helpers
# ─────────────────────────────────────────────

def send_msg(conn, data):
    raw = json.dumps(data).encode()
    conn.sendall(len(raw).to_bytes(4, "big") + raw)

def recv_msg(conn):
    length = int.from_bytes(_recv_exact(conn, 4), "big")
    return json.loads(_recv_exact(conn, length).decode())

def _recv_exact(conn, n):
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed by peer")
        buf += chunk
    return buf

def p(msg):
    """Prints to stderr — guaranteed unbuffered on Windows."""
    sys.stderr.write(str(msg) + "\n")
    sys.stderr.flush()

# ─────────────────────────────────────────────
# RSA host key
# ─────────────────────────────────────────────

def generate_rsa_host_key():
    log.info("Generating RSA host key pair (2048-bit)...")
    return rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )

def get_public_key_bytes(private_key):
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

# ─────────────────────────────────────────────
# Diffie-Hellman
# ─────────────────────────────────────────────

def generate_dh_parameters():
    log.info("Loading DH Group 14 parameters (RFC 3526)...")
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
        "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16
    )
    return p, 2

def dh_generate_server_keypair(p, g):
    params = DHParameterNumbers(p, g).parameters(default_backend())
    priv = params.generate_private_key()
    return priv, priv.public_key().public_numbers().y

def dh_compute_shared_secret(server_private, client_pub_int, p, g):
    pub = DHPublicNumbers(client_pub_int, DHParameterNumbers(p, g)).public_key(default_backend())
    secret = server_private.exchange(pub)
    log.info("Shared DH secret computed successfully.")
    return secret

# ─────────────────────────────────────────────
# Session key derivation
# ─────────────────────────────────────────────

def derive_session_keys(shared_secret, client_nonce, server_nonce):
    def derive(label, length):
        h = hashlib.sha256(shared_secret + client_nonce + server_nonce + label.encode()).digest()
        while len(h) < length:
            h += hashlib.sha256(h + shared_secret + label.encode()).digest()
        return h[:length]
    return {
        "encryption_key": derive("encryption_key", 32),
        "mac_key":        derive("mac_key", 32),
        "iv":             derive("iv", 16),
    }

# ─────────────────────────────────────────────
# Digital signature
# ─────────────────────────────────────────────

def compute_exchange_hash(client_nonce, server_nonce, client_pub_int, server_pub_int, shared_secret):
    data = (client_nonce + server_nonce +
            client_pub_int.to_bytes(256, "big") +
            server_pub_int.to_bytes(256, "big") +
            shared_secret)
    return hashlib.sha256(data).digest()

def sign_exchange_hash(host_private_key, exchange_hash):
    sig = host_private_key.sign(exchange_hash, padding.PKCS1v15(), hashes.SHA256())
    log.info("Exchange hash signed with server host key (RSA-PKCS1v15-SHA256).")
    return sig

# ─────────────────────────────────────────────
# Decrypt incoming message
# ─────────────────────────────────────────────

def decrypt_message(packet, encryption_key, mac_key, iv):
    ciphertext = bytes.fromhex(packet["ciphertext"])
    received_mac = bytes.fromhex(packet["hmac"])

    expected_mac = hmac.new(mac_key, ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(expected_mac, received_mac):
        raise ValueError("HMAC verification failed — message may have been tampered!")

    cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv), backend=default_backend())
    padded = cipher.decryptor().update(ciphertext) + cipher.decryptor().finalize()

    # Rebuild decryptor (can't reuse after finalize)
    cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor()
    padded = dec.update(ciphertext) + dec.finalize()

    pad_len = padded[-1]
    return padded[:-pad_len].decode("utf-8")

# ─────────────────────────────────────────────
# Handshake handler
# ─────────────────────────────────────────────

def handle_handshake(conn, addr, host_private_key, dh_params):
    session_start = time.time()
    log.info("=" * 60)
    log.info(f"NEW CONNECTION from {addr[0]}:{addr[1]}")
    log.info("=" * 60)
    p("\n" + "=" * 55)
    p("  Client connected! Initiating handshake...")
    p("=" * 55)

    try:
        # Phase 1 — Version exchange
        log.info("[Phase 1] >>> Protocol Version Exchange")
        p("\n[Phase 1] Protocol version exchange...")
        send_msg(conn, {"type": "SSH_VERSION", "version": "SSH-2.0-SimplSSH_1.0"})
        log.info("[Phase 1] --> Sent server version: SSH-2.0-SimplSSH_1.0")

        client_version = recv_msg(conn)
        if client_version.get("type") != "SSH_VERSION":
            raise ValueError("Expected SSH_VERSION from client")
        log.info(f"[Phase 1] <-- Received client version: {client_version['version']}")
        p(f"  ✔ Client version: {client_version['version']}")

        # Phase 2 — Algorithm negotiation
        log.info("[Phase 2] >>> Algorithm Negotiation (KEXINIT)")
        p("\n[Phase 2] Algorithm negotiation...")
        send_msg(conn, {"type": "KEXINIT", "algorithms": SUPPORTED_ALGOS})
        log.info(f"[Phase 2] --> Sent server algorithm proposals: {SUPPORTED_ALGOS}")

        client_kexinit = recv_msg(conn)
        if client_kexinit.get("type") != "KEXINIT":
            raise ValueError("Expected KEXINIT from client")
        client_algos = client_kexinit["algorithms"]
        log.info(f"[Phase 2] <-- Received client algorithm proposals: {client_algos}")

        agreed_kex = list(set(SUPPORTED_ALGOS["kex"]) & set(client_algos["kex"]))[0]
        agreed_enc = list(set(SUPPORTED_ALGOS["encryption"]) & set(client_algos["encryption"]))[0]
        agreed_mac = list(set(SUPPORTED_ALGOS["mac"]) & set(client_algos["mac"]))[0]
        log.info(f"[Phase 2] ✔ Agreed: kex={agreed_kex} | cipher={agreed_enc} | mac={agreed_mac}")
        p(f"  ✔ Agreed kex      : {agreed_kex}")
        p(f"  ✔ Agreed cipher   : {agreed_enc}")
        p(f"  ✔ Agreed MAC      : {agreed_mac}")

        # Phase 3 — DH key exchange
        log.info("[Phase 3] >>> Diffie-Hellman Key Exchange")
        p("\n[Phase 3] Diffie-Hellman key exchange...")
        dh_p, dh_g = dh_params
        server_private, server_pub_int = dh_generate_server_keypair(dh_p, dh_g)
        log.info(f"[Phase 3] Server DH public key: {hex(server_pub_int)[:32]}...")

        kex_init = recv_msg(conn)
        if kex_init.get("type") != "KEX_INIT":
            raise ValueError("Expected KEX_INIT from client")
        client_pub_int = int(kex_init["dh_public"])
        client_nonce = bytes.fromhex(kex_init["nonce"])
        log.info(f"[Phase 3] <-- Client DH public key: {hex(client_pub_int)[:32]}...")
        log.info(f"[Phase 3] <-- Client nonce: {client_nonce.hex()[:16]}... ({len(client_nonce)} bytes)")
        log.info(f"[Phase 3] Client DH key bit-length: {client_pub_int.bit_length()} bits")
        p("  ✔ Received client DH public key and nonce")

        server_nonce = os.urandom(32)
        log.info(f"[Phase 3] Generated server nonce: {server_nonce.hex()[:16]}... ({len(server_nonce)} bytes)")

        host_pub_bytes = get_public_key_bytes(host_private_key)
        send_msg(conn, {
            "type": "KEX_REPLY",
            "dh_public": str(server_pub_int),
            "nonce": server_nonce.hex(),
            "host_public_key": host_pub_bytes.decode()
        })
        log.info(f"[Phase 3] --> Sent server DH public key, nonce, RSA host key ({len(host_pub_bytes)} bytes)")
        p("  ✔ Sent server DH public key and host key to client")

        # Phase 4 — Server authentication
        log.info("[Phase 4] >>> Server Authentication (Digital Signature)")
        p("\n[Phase 4] Server authentication (digital signature)...")
        shared_secret = dh_compute_shared_secret(server_private, client_pub_int, dh_p, dh_g)
        log.info(f"[Phase 4] Shared secret computed ({len(shared_secret)} bytes): {shared_secret.hex()[:16]}...")

        exchange_hash = compute_exchange_hash(
            client_nonce, server_nonce, client_pub_int, server_pub_int, shared_secret)
        log.info(f"[Phase 4] Exchange hash (SHA-256): {exchange_hash.hex()}")

        signature = sign_exchange_hash(host_private_key, exchange_hash)
        log.info(f"[Phase 4] RSA signature ({len(signature)} bytes): {signature.hex()[:32]}...")

        send_msg(conn, {"type": "HOST_SIGNATURE", "signature": signature.hex(), "exchange_hash": exchange_hash.hex()})
        log.info("[Phase 4] --> Sent HOST_SIGNATURE to client for verification")
        p("  ✔ Signed exchange hash and sent signature to client")

        # Phase 5 — Session key derivation
        log.info("[Phase 5] >>> Session Key Derivation")
        p("\n[Phase 5] Deriving session keys...")
        session_keys = derive_session_keys(shared_secret, client_nonce, server_nonce)
        log.info(f"[Phase 5] encryption_key: {session_keys['encryption_key'].hex()[:16]}... (32 bytes, AES-256)")
        log.info(f"[Phase 5] mac_key:        {session_keys['mac_key'].hex()[:16]}... (32 bytes, HMAC-SHA256)")
        log.info(f"[Phase 5] iv:             {session_keys['iv'].hex()} (16 bytes)")
        log.info("[Phase 5] ✔ All session keys derived successfully")
        p("  ✔ Session keys derived (AES-256 + HMAC-SHA256)")

        # Phase 6 — NEWKEYS
        log.info("[Phase 6] >>> NEWKEYS Confirmation")
        p("\n[Phase 6] NEWKEYS confirmation...")
        client_newkeys = recv_msg(conn)
        if client_newkeys.get("type") != "NEWKEYS":
            raise ValueError("Expected NEWKEYS from client")
        log.info("[Phase 6] <-- Received NEWKEYS from client")
        p("  ✔ Received NEWKEYS from client")

        send_msg(conn, {"type": "NEWKEYS"})
        log.info("[Phase 6] --> Sent NEWKEYS to client")
        p("  ✔ Sent NEWKEYS to client")

        # Success
        elapsed = round(time.time() - session_start, 3)
        p("\n" + "=" * 55)
        p("  ✅ Handshake successful! Secure channel established.")
        p("=" * 55)
        log.info("=" * 60)
        log.info(f"[SUCCESS] Handshake complete in {elapsed}s — {addr[0]}:{addr[1]}")
        log.info("=" * 60)

        send_msg(conn, {"type": "HANDSHAKE_COMPLETE", "message": "Secure channel established."})

        # Encrypted messaging session
        p("\n" + "─" * 55)
        p("  📨 ENCRYPTED MESSAGE SESSION — waiting for client...")
        p("─" * 55 + "\n")

        while True:
            packet = recv_msg(conn)

            if packet.get("type") == "SESSION_END":
                log.info("Client ended the session.")
                p("  Client has ended the session.")
                break

            if packet.get("type") == "ENCRYPTED_MSG":
                try:
                    plaintext = decrypt_message(
                        packet,
                        session_keys["encryption_key"],
                        session_keys["mac_key"],
                        session_keys["iv"]
                    )
                    p(f"  📩 Client says (decrypted): \"{plaintext}\"")
                    log.info(f"Received and decrypted: \"{plaintext}\"")
                    send_msg(conn, {"type": "ACK", "message": f"Message received: '{plaintext}'"})
                    log.info("ACK sent to client.")
                except ValueError as e:
                    log.error(f"Decryption failed: {e}")
                    p(f"  ❌ {e}")
                    send_msg(conn, {"type": "ACK", "message": f"ERROR: {e}"})

    except Exception as e:
        elapsed = round(time.time() - session_start, 3)
        log.error("=" * 60)
        log.error(f"[FAILURE] Handshake failed after {elapsed}s — {type(e).__name__}: {e}")
        log.error("=" * 60)
        p(f"\n  ❌ Handshake failed: {e}")
        try:
            send_msg(conn, {"type": "ERROR", "message": str(e)})
        except Exception:
            pass
    finally:
        conn.close()
        log.info(f"Connection with {addr[0]}:{addr[1]} closed.")

# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────

def main():
    p("\n" + "=" * 55)
    p("   Simplified SSH Server - Starting Up")
    p("=" * 55)

    host_private_key = generate_rsa_host_key()

    p("  Pre-generating DH parameters (one-time)...")
    dh_params = generate_dh_parameters()
    p("  DH parameters ready.\n")

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((HOST, PORT))
    server_sock.listen(5)

    p(f"\n  Server listening on {HOST}:{PORT}")
    p("  Awaiting client connections...\n")
    log.info(f"Server listening on {HOST}:{PORT}")

    while True:
        try:
            conn, addr = server_sock.accept()
            handle_handshake(conn, addr, host_private_key, dh_params)
        except KeyboardInterrupt:
            p("\n\n  Server shutting down...")
            log.info("Server stopped by user.")
            break
        except Exception as e:
            log.error(f"Unexpected error: {e}")

    server_sock.close()

if __name__ == "__main__":
    main()