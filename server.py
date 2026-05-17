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
