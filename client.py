
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

def run_handshake(conn):
    p("\n" + "=" * 55)
    p("   Welcome to Simplified SSH Client")
    p("=" * 55)
    p("\n  Attempting to connect to the SSH server...")
    p("  Starting handshake protocol...\n")
    log.info("Handshake started.")

    try:
        
        log.info("[Phase 1] Protocol version exchange")
        p("[Phase 1] Protocol version exchange...")
        server_version = recv_msg(conn)
        if server_version.get("type") != "SSH_VERSION":
            raise ValueError("Expected SSH_VERSION from server")
        log.info(f"Server version: {server_version['version']}")
        p(f"   Server version: {server_version['version']}")
        send_msg(conn, {"type": "SSH_VERSION", "version": "SSH-2.0-SimplSSH_Client_1.0"})

       
        log.info("[Phase 2] Algorithm negotiation (KEXINIT)")
        p("\n[Phase 2] Algorithm negotiation...")
        server_kexinit = recv_msg(conn)
        if server_kexinit.get("type") != "KEXINIT":
            raise ValueError("Expected KEXINIT from server")
        send_msg(conn, {"type": "KEXINIT", "algorithms": SUPPORTED_ALGOS})

        server_algos = server_kexinit["algorithms"]
        agreed_kex = list(set(SUPPORTED_ALGOS["kex"]) & set(server_algos["kex"]))[0]
        agreed_enc = list(set(SUPPORTED_ALGOS["encryption"]) & set(server_algos["encryption"]))[0]
        agreed_mac = list(set(SUPPORTED_ALGOS["mac"]) & set(server_algos["mac"]))[0]
        log.info(f"Agreed: kex={agreed_kex}, enc={agreed_enc}, mac={agreed_mac}")
        p(f"   Agreed kex      : {agreed_kex}")
        p(f"   Agreed cipher   : {agreed_enc}")
        p(f"   Agreed MAC      : {agreed_mac}")

        
        log.info("[Phase 3] Diffie-Hellman key exchange")
        p("\n[Phase 3] Diffie-Hellman key exchange...")
        dh_p, dh_g = get_dh_group14_params()
        client_private, client_pub_int = dh_generate_client_keypair(dh_p, dh_g)
        client_nonce = os.urandom(32)
        send_msg(conn, {"type": "KEX_INIT", "dh_public": str(client_pub_int), "nonce": client_nonce.hex()})
        p("   Sent client DH public key and nonce to server")

        kex_reply = recv_msg(conn)
        if kex_reply.get("type") != "KEX_REPLY":
            raise ValueError("Expected KEX_REPLY from server")
        server_pub_int = int(kex_reply["dh_public"])
        server_nonce = bytes.fromhex(kex_reply["nonce"])
        host_pub_key_pem = kex_reply["host_public_key"]
        log.info("Received server DH public key, nonce, and host public key.")
        p("  ✔ Received server DH public key and host key")

        
        log.info("[Phase 4] Server authentication")
        p("\n[Phase 4] Server authentication (verifying signature)...")
        shared_secret = dh_compute_shared_secret(client_private, server_pub_int, dh_p, dh_g)

        sig_msg = recv_msg(conn)
        if sig_msg.get("type") != "HOST_SIGNATURE":
            raise ValueError("Expected HOST_SIGNATURE from server")

        exchange_hash = compute_exchange_hash(
            client_nonce, server_nonce, client_pub_int, server_pub_int, shared_secret)

        if not verify_server_signature(host_pub_key_pem, sig_msg["signature"], exchange_hash):
            raise ValueError("Server identity could NOT be verified! Possible MITM attack!")
        p("   Server identity verified via digital signature")
        p("   No man-in-the-middle attack detected")

        
        log.info("[Phase 5] Deriving session keys")
        p("\n[Phase 5] Deriving session keys...")
        session_keys = derive_session_keys(shared_secret, client_nonce, server_nonce)
        log.info("Session keys derived.")
        p("  ✔ Session keys derived (AES-256 + HMAC-SHA256)")

        
        log.info("[Phase 6] NEWKEYS exchange")
        p("\n[Phase 6] NEWKEYS confirmation...")
        send_msg(conn, {"type": "NEWKEYS"})
        p("  ✔ Sent NEWKEYS to server")
        server_newkeys = recv_msg(conn)
        if server_newkeys.get("type") != "NEWKEYS":
            raise ValueError("Expected NEWKEYS from server")
        p("  ✔ Received NEWKEYS from server")

        
        final = recv_msg(conn)
        if final.get("type") == "HANDSHAKE_COMPLETE":
            p("\n" + "=" * 55)
            p("   Server identity verified. Handshake successful.")
            p("   Secure channel established.")
            p("=" * 55)
            log.info("Handshake complete. Secure session established.")

            # Interactive encrypted session
            p("\n" + "─" * 55)
            p("  📨 SECURE SESSION ACTIVE")
            p("  Commands:")
            p("    send <message>  — send an encrypted message")
            p("    help            — show this help")
            p("    exit            — close the session")
            p("─" * 55 + "\n")

            while True:
                try:
                    raw = input("  [ssh]> ").strip()
                    sys.stdout.flush()
                except (EOFError, KeyboardInterrupt):
                    p("")
                    raw = "exit"

                if not raw:
                    continue

                if raw.lower() == "exit":
                    send_msg(conn, {"type": "SESSION_END"})
                    log.info("Session ended by user.")
                    p("\n  Session closed. Goodbye.")
                    break

                elif raw.lower() == "help":
                    p("  Commands:")
                    p("    send <message>  — encrypt and send a message to the server")
                    p("    help            — show this help")
                    p("    exit            — close the session")
                    p("")

                elif raw.lower().startswith("send "):
                    msg = raw[5:].strip()
                    if not msg:
                        p("  Usage: send <message>\n")
                        continue
                    packet = encrypt_message(msg, session_keys["encryption_key"],
                                             session_keys["mac_key"], session_keys["iv"])
                    send_msg(conn, packet)
                    log.info(f"Sent encrypted message: \"{msg}\"")
                    p(f"  → Encrypted ciphertext : {packet['ciphertext'][:40]}...")
                    p(f"  → HMAC-SHA256          : {packet['hmac'][:40]}...")

                    ack = recv_msg(conn)
                    if ack.get("type") == "ACK":
                        p(f"  ← Server says          : \"{ack['message']}\"")
                        log.info(f"Server ACK: {ack['message']}")
                    p("")

                else:
                    p(f"  Unknown command: '{raw}'. Type 'help' for available commands.\n")

            return True

    except Exception as e:
        log.error(f"Handshake error: {e}")
        p(f"\n   Handshake failed: {e}")
        return False

# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────

def main():
    log.info(f"Connecting to SSH server at {HOST}:{PORT}...")
    try:
        conn = socket.create_connection((HOST, PORT), timeout=10)
        success = run_handshake(conn)
        conn.close()
        if not success:
            p("  Connection terminated due to handshake failure.\n")
    except ConnectionRefusedError:
        p(f"\n   Could not connect to server at {HOST}:{PORT}.")
        p("     Make sure the server is running first.\n")
        log.error("Connection refused. Is the server running?")
    except Exception as e:
        p(f"\n   Unexpected error: {e}\n")
        log.error(f"Unexpected error: {e}")

if __name__ == "__main__":
    main()

