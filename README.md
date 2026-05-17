# SSH Handshake Simulation (Python)

A simplified educational implementation of the **SSH-2 handshake protocol** using Python sockets and modern cryptography primitives.

This project demonstrates:

- Protocol version exchange
- Algorithm negotiation (`KEXINIT`)
- Diffie-Hellman key exchange
- RSA-based server authentication
- Session key derivation
- Secure handshake completion (`NEWKEYS`)

The implementation is designed for learning purposes and simulates the main phases of a real SSH connection.

---

# Project Structure

```text
ssh_handshake/
├── client.py
├── server.py
├── requirements.txt
├── .gitignore
└── README.md
```

---

# Requirements

- Python 3.8+
- pip

Install dependencies:

```bash
pip install -r requirements.txt
```

Required package:

- `cryptography`

---

# How to Run

Open **two terminals**.

## 1. Start the Server

```bash
python server.py
```

The server starts listening on:

```text
127.0.0.1:2222
```

---

## 2. Start the Client

```bash
python client.py
```

The client connects automatically and performs the SSH handshake simulation.

> Important: Start the server before running the client.

---

# Handshake Phases

## Phase 1 — Protocol Version Exchange

Client and server exchange SSH version strings.

Example:

```text
SSH-2.0-SimplSSH_Client_1.0
SSH-2.0-SimplSSH_Server_1.0
```

This confirms compatibility before cryptographic operations begin.

---

## Phase 2 — Algorithm Negotiation (KEXINIT)

Both sides exchange supported algorithms and agree on:

| Category | Algorithm |
|---|---|
| Key Exchange | diffie-hellman-group14-sha256 |
| Encryption | aes256-cbc |
| MAC | hmac-sha256 |
| Compression | none |

---

## Phase 3 — Diffie-Hellman Key Exchange

The client and server:

1. Generate DH key pairs
2. Exchange public keys
3. Independently compute the same shared secret

The shared secret is never transmitted directly.

This implementation uses:

- RFC 3526 Group 14
- 2048-bit prime
- Generator `g = 2`

---

## Phase 4 — Server Authentication

The server authenticates itself by:

1. Creating a SHA-256 exchange hash
2. Signing the hash using its RSA private key
3. Sending the signature to the client

The client verifies the signature using the server’s public key.

This prevents Man-in-the-Middle (MITM) attacks.

---

## Phase 5 — Session Key Derivation

The shared secret and exchanged nonces are used to derive:

- AES encryption key
- HMAC key
- Initialization Vector (IV)

Key derivation uses SHA-256 hashing.

---

## Phase 6 — NEWKEYS Confirmation

Both sides send `NEWKEYS` messages indicating that:

- The handshake is complete
- Future communication would use the derived session keys

---

# Security Features

| Threat | Protection |
|---|---|
| MITM attacks | RSA signature verification |
| Eavesdropping | Diffie-Hellman shared secret |
| Replay attacks | Session-specific nonces |
| Weak parameters | RFC 3526 Group 14 |

---

# Example Output

## Server

```text
[Phase 1] Protocol version exchange...
✔ Client version received

[Phase 2] Algorithm negotiation...
✔ Agreed cipher: aes256-cbc

[Phase 3] Diffie-Hellman key exchange...
✔ Shared secret established

[Phase 4] Server authentication...
✔ Signature verified

[Phase 5] Deriving session keys...
✔ Session keys generated

[Phase 6] NEWKEYS confirmation...
✔ Handshake successful
```

---

# Educational Purpose

This project is intended for:

- Cybersecurity students
- Networking courses
- Cryptography learning
- Understanding SSH internals

It is not intended for production use.

---

# Technologies Used

- Python
- TCP sockets
- RSA
- Diffie-Hellman
- SHA-256
- AES concepts
- HMAC
- `cryptography` library

---

# Authors

Developed as an educational SSH handshake simulation project.