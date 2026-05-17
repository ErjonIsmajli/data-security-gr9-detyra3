
import os
import sys
import socket
import json
import logging
import hashlib
import hmac

os.environ["PYTHONUNBUFFERED"] = "1"

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.dh import DHParameterNumbers, DHPublicNumbers
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class FlushHandler(logging.StreamHandler):
    def emit(self, record):
        super().emit(record)
        self.flush()
        sys.stdout.flush()

_log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "client.log")
_fmt = logging.Formatter("[%(asctime)s] [CLIENT] %(levelname)s: %(message)s")
_fh = logging.FileHandler(_log_path, mode="a", encoding="utf-8")
_fh.setFormatter(_fmt)
_ch = FlushHandler(sys.stdout)
_ch.setFormatter(_fmt)
logging.root.setLevel(logging.INFO)
logging.root.handlers = []
logging.root.addHandler(_fh)
logging.root.addHandler(_ch)
log = logging.getLogger(__name__)

HOST = "127.0.0.1"
PORT = 2222

SUPPORTED_ALGOS = {
    "kex": ["diffie-hellman-group14-sha256"],
    "encryption": ["aes256-cbc"],
    "mac": ["hmac-sha256"],
    "compression": ["none"]
}


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
    """print + immediate flush"""
    print(msg, flush=True)

    
def get_dh_group14_params():
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

def dh_generate_client_keypair(p, g):
    params = DHParameterNumbers(p, g).parameters(default_backend())
    priv = params.generate_private_key()
    log.info("Client DH key pair generated.")
    return priv, priv.public_key().public_numbers().y

def dh_compute_shared_secret(client_private, server_pub_int, p, g):
    pub = DHPublicNumbers(server_pub_int, DHParameterNumbers(p, g)).public_key(default_backend())
    secret = client_private.exchange(pub)
    log.info("Shared DH secret computed successfully.")
    return secret



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


def compute_exchange_hash(client_nonce, server_nonce, client_pub_int, server_pub_int, shared_secret):
    data = (client_nonce + server_nonce +
            client_pub_int.to_bytes(256, "big") +
            server_pub_int.to_bytes(256, "big") +
            shared_secret)
    return hashlib.sha256(data).digest()

def verify_server_signature(host_pub_key_pem, signature_hex, exchange_hash):
    log.info("Verifying server identity via RSA signature...")
    try:
        public_key = serialization.load_pem_public_key(host_pub_key_pem.encode(), backend=default_backend())
        public_key.verify(bytes.fromhex(signature_hex), exchange_hash, padding.PKCS1v15(), hashes.SHA256())
        log.info("Server signature VERIFIED successfully.")
        return True
    except Exception as e:
        log.error(f"Signature verification FAILED: {e}")
        return False
    
    
def encrypt_message(plaintext, encryption_key, mac_key, iv):
    raw = plaintext.encode("utf-8")
    pad_len = 16 - (len(raw) % 16)
    raw += bytes([pad_len] * pad_len)

    cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    ciphertext = enc.update(raw) + enc.finalize()

    mac = hmac.new(mac_key, ciphertext, hashlib.sha256).digest()
    log.info(f"Message encrypted: {len(plaintext)} chars → {len(ciphertext)} bytes ciphertext")
    log.info(f"HMAC-SHA256: {mac.hex()[:16]}...")
    return {"type": "ENCRYPTED_MSG", "ciphertext": ciphertext.hex(), "hmac": mac.hex()}