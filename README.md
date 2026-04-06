# FTP

FTP server & client by Daniel J Murphy

Bidirectionally synchronizes ```~/Shared - Server``` (server-side) with ```~/Shared - Client``` (client-side) across all connected clients over an encrypted connection.

---

## 🔐 Security Overview

- After AES session key generation, **all communication is encrypted end-to-end**.
- Session keys are derived using **X25519 Diffie-Hellman key exchange**.
- The server authenticates itself using a CA-signed identity mechanism.
- The client verifies all server messages before processing them.
- Clients authenticate using **Ed25519 digital signatures**.

---

## 🔄 Protocol Flow

### 1. Authentication + Key Exchange

#### Client:
- Loads Ed25519 public/private key pair
- If keys are missing/invalid → regenerate
- Sends a blank request to trigger auth setup
Client:
- Generates X25519 key pair
- Sends X25519 public key

Server:
- Generates X25519 key pair
- Sends server X25519 public key
- Both sides derive shared secret
- Both sides derive AES session key from shared secret

---

## 🔐 After AES Key Generation

All communication from this point onward is encrypted using AES derived from the X25519 shared secret.

---

## 🔐 Authentication Challenge

Server:
- Generates 128-byte random token
- Sends token to client

Client:
- Signs token using Ed25519 private key
- Sends signature to server

Server:
- Verifies signature against stored client public keys (indexed by username for performance)

If signature is valid:
- Authentication succeeds
- Proceed to request phase ("body")

If signature is invalid:
- Server prompts admin approval (yes/no)

If admin approves:
- Server requests client public key
- Re-verifies signature using updated key
- If valid → proceed
- If invalid → reject connection

---

## 📦 Request "body"

After successful authentication, all requests are encrypted using the AES session key.

---

### 📄 JSON (file index sync)

if request_type == b'JSON':

Server:
- Serializes file index
- Sends file index in encrypted chunks

---

### ⬇️ DOWNLOAD (DOWN)

Client:
- Sends requested file path

Server:
- Computes SHA-512 hash of file
- Sends file hash
- Sends file data in encrypted chunks

---

### ⬆️ UPLOAD (UP)

Client:
- Sends file path
- Sends SHA-512 hash
- Sends file data in encrypted chunks

---

## 🔑 Core Security Properties

- All post-auth traffic is encrypted with AES session key (there are exceptions, including ack and sending the username)
- AES key derived via X25519 Diffie-Hellman exchange
- Client identity verified using Ed25519 signatures
- Server enforces authentication and requires admin approval for each new client connection
- File integrity ensured using SHA-512 hashing
- Client password never reaches the server and is exclusivly used to encrypt the client private identity key
