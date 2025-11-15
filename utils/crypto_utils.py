"""Utility crypto functions: DH helpers, key derivation, AES-GCM encrypt/decrypt
This implementation is for demo/educational use only.
"""
import hashlib
import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# --- Toy DH utilities (DEMO ONLY) ---
# In a real system use standardized groups (RFC 3526) or ECDH.

def generate_dh_params():
    # For demo we use a fixed safe-ish prime (not production-grade).
    p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1
    g = 2
    return p, g


def dh_generate_private_key(p):
    return int.from_bytes(os.urandom(32), 'big') % (p - 3) + 2


def dh_compute_public(g, private, p):
    return pow(g, private, p)


def dh_compute_shared(public_other, private, p):
    return pow(public_other, private, p)

# --- Key derivation ---

def derive_aes_key(shared_secret: int) -> bytes:
    s_bytes = str(shared_secret).encode()
    return hashlib.sha256(s_bytes).digest()

# --- AES-GCM helpers ---

def aes_gcm_encrypt(aes_key: bytes, plaintext: bytes, aad: bytes = b'') -> dict:
    iv = get_random_bytes(12)
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
    if aad:
        cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return {'iv': iv, 'ct': ciphertext, 'tag': tag}


def aes_gcm_decrypt(aes_key: bytes, iv: bytes, ciphertext: bytes, tag: bytes, aad: bytes = b'') -> bytes:
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
    if aad:
        cipher.update(aad)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext
