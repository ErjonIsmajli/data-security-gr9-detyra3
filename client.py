
import socket
import json
import os
import logging
import hashlib
import hmac
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.dh import DHParameterNumbers, DHPublicNumbers
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

import sys

class FlushStreamHandler(logging.StreamHandler):
    """StreamHandler that flushes after every record so logs appear immediately in terminal."""
    def emit(self, record):
        super().emit(record)
        self.flush()

_log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "client.log")

_fmt = logging.Formatter("[%(asctime)s] [CLIENT] %(levelname)s: %(message)s")
_file_handler = logging.FileHandler(_log_path, mode="a", encoding="utf-8")
_file_handler.setFormatter(_fmt)
_console_handler = FlushStreamHandler(sys.stdout)
_console_handler.setFormatter(_fmt)

logging.root.setLevel(logging.INFO)
logging.root.handlers = []  
logging.root.addHandler(_file_handler)
logging.root.addHandler(_console_handler)
log = logging.getLogger(__name__)

HOST = "127.0.0.1"
PORT = 2222


SUPPORTED_ALGOS = {
    "kex": ["diffie-hellman-group14-sha256"],
    "encryption": ["aes256-cbc"],
    "mac": ["hmac-sha256"],
    "compression": ["none"]
}


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

def get_dh_group14_params():
    """
    Return the standard DH Group 14 parameters (RFC 3526).
    Same prime p and generator g=2 must be used by both client and server.
    """
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


def dh_generate_client_keypair(p: int, g: int):
    """Generate the client's DH private/public key pair."""
    from cryptography.hazmat.primitives.asymmetric.dh import DHParameterNumbers
    pn = DHParameterNumbers(p, g)
    params = pn.parameters(default_backend())
    client_private = params.generate_private_key()
    client_pub_int = client_private.public_key().public_numbers().y
    log.info("Client DH key pair generated.")
    return client_private, client_pub_int

def dh_compute_shared_secret(client_private, server_pub_int: int, p: int, g: int) -> bytes:
    """Compute the DH shared secret using the server's public key."""
    pn = DHParameterNumbers(p, g)
    pub_numbers = DHPublicNumbers(server_pub_int, pn)
    server_pub_key = pub_numbers.public_key(default_backend())
    shared_secret = client_private.exchange(server_pub_key)
    log.info("Shared DH secret computed successfully.")
    return shared_secret


def derive_session_keys(shared_secret: bytes, client_nonce: bytes, server_nonce: bytes) -> dict:
    """
    Derive session keys from the shared secret.
    Must be identical to the server's derivation for symmetric keys to match.
    """
    log.info("Deriving session keys from shared secret...")

    def derive(label: str, length: int) -> bytes:
        h = hashlib.sha256(shared_secret + client_nonce + server_nonce + label.encode()).digest()
        while len(h) < length:
            h += hashlib.sha256(h + shared_secret + label.encode()).digest()
        return h[:length]

    keys = {
        "encryption_key": derive("encryption_key", 32),
        "mac_key": derive("mac_key", 32),
        "iv": derive("iv", 16),
    }
    log.info("Session keys derived: encryption_key(32B), mac_key(32B), iv(16B)")
    return keys


def verify_server_signature(host_pub_key_pem: str, signature_hex: str,
                             exchange_hash: bytes) -> bool:
    """
    Verify the server's digital signature over the exchange hash.
    This authenticates the server and prevents MITM attacks.
    """
    log.info("Verifying server identity via RSA signature...")
    try:
        public_key = serialization.load_pem_public_key(
            host_pub_key_pem.encode(),
            backend=default_backend()
        )
        signature = bytes.fromhex(signature_hex)
        public_key.verify(
            signature,
            exchange_hash,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        log.info("Server signature VERIFIED successfully.")
        return True
    except Exception as e:
        log.error(f"Signature verification FAILED: {e}")
        return False


def compute_exchange_hash(client_nonce: bytes, server_nonce: bytes,
                           client_pub_int: int, server_pub_int: int,
                           shared_secret: bytes) -> bytes:
    """Recompute the exchange hash to verify the server's signature."""
    data = (
        client_nonce +
        server_nonce +
        client_pub_int.to_bytes(256, "big") +
        server_pub_int.to_bytes(256, "big") +
        shared_secret
    )
    return hashlib.sha256(data).digest()