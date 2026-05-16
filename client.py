
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

def run_handshake(conn: socket.socket) -> bool:
   
    print("\n" + "="*55)
    print("   Welcome to Simplified SSH Client")
    print("="*55)
    print("\n  Attempting to connect to the SSH server...")
    print("  Starting handshake protocol...\n")
    log.info("Handshake started.")

    try:
        
        log.info("[Phase 1] Protocol version exchange")
        print("[Phase 1] Protocol version exchange...")

        server_version = recv_msg(conn)
        if server_version.get("type") != "SSH_VERSION":
            raise ValueError("Expected SSH_VERSION from server")
        log.info(f"Server version: {server_version['version']}")
        print(f"  ✔ Server version: {server_version['version']}")

        client_version = {"type": "SSH_VERSION", "version": "SSH-2.0-SimplSSH_Client_1.0"}
        send_msg(conn, client_version)

        
        log.info("[Phase 2] Algorithm negotiation (KEXINIT)")
        print("\n[Phase 2] Algorithm negotiation...")

        server_kexinit = recv_msg(conn)
        if server_kexinit.get("type") != "KEXINIT":
            raise ValueError("Expected KEXINIT from server")

        send_msg(conn, {"type": "KEXINIT", "algorithms": SUPPORTED_ALGOS})

        
        server_algos = server_kexinit["algorithms"]
        agreed_kex = list(set(SUPPORTED_ALGOS["kex"]) & set(server_algos["kex"]))[0]
        agreed_enc = list(set(SUPPORTED_ALGOS["encryption"]) & set(server_algos["encryption"]))[0]
        agreed_mac = list(set(SUPPORTED_ALGOS["mac"]) & set(server_algos["mac"]))[0]
        log.info(f"Agreed: kex={agreed_kex}, enc={agreed_enc}, mac={agreed_mac}")
        print(f"   Agreed kex      : {agreed_kex}")
        print(f"   Agreed cipher   : {agreed_enc}")
        print(f"   Agreed MAC      : {agreed_mac}")

       
        log.info("[Phase 3] Diffie-Hellman key exchange")
        print("\n[Phase 3] Diffie-Hellman key exchange...")

        p, g = get_dh_group14_params()
        client_private, client_pub_int = dh_generate_client_keypair(p, g)
        client_nonce = os.urandom(32)

        send_msg(conn, {
            "type": "KEX_INIT",
            "dh_public": str(client_pub_int),
            "nonce": client_nonce.hex()
        })
        print("   Sent client DH public key and nonce to server")

        kex_reply = recv_msg(conn)
        if kex_reply.get("type") != "KEX_REPLY":
            raise ValueError("Expected KEX_REPLY from server")

        server_pub_int = int(kex_reply["dh_public"])
        server_nonce = bytes.fromhex(kex_reply["nonce"])
        host_pub_key_pem = kex_reply["host_public_key"]
        log.info("Received server DH public key, nonce, and host public key.")
        print("   Received server DH public key and host key")

       
        log.info("[Phase 4] Server authentication")
        print("\n[Phase 4] Server authentication (verifying signature)...")

        shared_secret = dh_compute_shared_secret(client_private, server_pub_int, p, g)

        
        sig_msg = recv_msg(conn)
        if sig_msg.get("type") != "HOST_SIGNATURE":
            raise ValueError("Expected HOST_SIGNATURE from server")

        
        exchange_hash = compute_exchange_hash(
            client_nonce, server_nonce,
            client_pub_int, server_pub_int,
            shared_secret
        )
        if not verify_server_signature(host_pub_key_pem, sig_msg["signature"], exchange_hash):
            raise ValueError("Server identity could NOT be verified! Possible MITM attack!")

        print("   Server identity verified via digital signature")
        print("   No man-in-the-middle attack detected")

        
        log.info("[Phase 5] Deriving session keys")
        print("\n[Phase 5] Deriving session keys...")

        session_keys = derive_session_keys(shared_secret, client_nonce, server_nonce)
        log.info("Session keys derived.")
        print("   Session keys derived (AES-256 + HMAC-SHA256)")

        
        log.info("[Phase 6] NEWKEYS exchange")
        print("\n[Phase 6] NEWKEYS confirmation...")

        send_msg(conn, {"type": "NEWKEYS"})
        print("   Sent NEWKEYS to server")

        server_newkeys = recv_msg(conn)
        if server_newkeys.get("type") != "NEWKEYS":
            raise ValueError("Expected NEWKEYS from server")
        print("   Received NEWKEYS from server")

        # ── Final confirmation ───────────────────────────────
        final = recv_msg(conn)
        if final.get("type") == "HANDSHAKE_COMPLETE":
            print("\n" + "="*55)
            print("   Server identity verified. Handshake successful.")
            print("   Secure channel established.")
            print("     You can now begin your session.")
            print("="*55 + "\n")
            log.info("Handshake complete. Secure session established.")
            return True

    except Exception as e:
        log.error(f"Handshake error: {e}")
        print(f"\n   Handshake failed: {e}")
        return False





def main():
    log.info(f"Connecting to SSH server at {HOST}:{PORT}...")
    try:
        conn = socket.create_connection((HOST, PORT), timeout=10)
        success = run_handshake(conn)
        conn.close()
        if not success:
            print("  Connection terminated due to handshake failure.\n")
    except ConnectionRefusedError:
        print(f"\n   Could not connect to server at {HOST}:{PORT}.")
        print("     Make sure the server is running first.\n")
        log.error("Connection refused. Is the server running?")
    except Exception as e:
        print(f"\n   Unexpected error: {e}\n")
        log.error(f"Unexpected error: {e}")


if __name__ == "__main__":
    main()