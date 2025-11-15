# Secure-Money-Transfer-Using-Diffie-Hellman (Demo)

This repository is an educational demo that shows how two parties can perform a secure money transfer by:
1. Performing a Diffie–Hellman (DH) key exchange to derive a shared secret.
2. Deriving a symmetric key from the shared secret.
3. Encrypting and authenticating transaction payloads using AES-GCM.
4. Relaying ciphertext via a simple Flask server (the server never sees plaintext).

**Warning:** This project is for learning and prototyping only. Do NOT use it as-is in production.
See the SECURITY section below for improvements you must make for any production use.

## Contents
- `server.py` – tiny Flask relay that stores public keys and forwards encrypted transactions.
- `client_example.py` – example client that registers a DH public key, derives a shared key with a recipient, encrypts a transaction, and sends it.
- `utils/crypto_utils.py` – DH helpers, KDF, and AES-GCM encryption/decryption utilities.
- `streamlit_app.py` – Streamlit GUI to register keys, perform DH with a recipient, send encrypted transactions, and check your inbox.
- `requirements.txt` – Python dependencies.
- `examples/run_demo.sh` – simple demo script to start server.

## Quick start (local demo)
1. Create a virtualenv and install dependencies:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```
2. Start the server in a terminal:
   ```bash
   python3 server.py
   ```
3. In another terminal register two users (run two separate clients or use the Streamlit app):
   - Run `python3 client_example.py` (edit `client_example.py` to set `user_id` to 'alice' or 'bob' and run twice to register both keys and send a message).
   - Or open `streamlit_app.py`: `streamlit run streamlit_app.py` (recommended, interactive).

## Security & production notes
- Replace toy DH parameters with **ECDH** (use `pyca/cryptography` library) or standardized safe MODP groups.
- Use HKDF (with salt & info) instead of a raw SHA256 of the shared secret.
- Authenticate public keys (signatures, certificates, or mutual TLS) to prevent active MITM attacks.
- Use persistent secure storage (not in-memory dictionaries) and enable access controls, rate-limiting, logging, and monitoring.
- Add replay protection (nonces and transaction IDs), input validation, and strong error handling.
- Perform threat modeling, security review, and regulatory compliance checks for any payment product.

