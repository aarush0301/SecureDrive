import os
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

NONCE_LEN = 12
TAG_LEN = 16


def new_data_key():
    """A fresh random 256-bit key (one per file)."""
    return get_random_bytes(32)


def encrypt_bytes(key, data, aad=b""):
    """AES-256-GCM. Returns: nonce (12 B) + tag (16 B) + ciphertext."""
    nonce = get_random_bytes(NONCE_LEN)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(aad)                       # authenticated, but not encrypted
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return nonce + tag + ciphertext


def decrypt_bytes(key, blob, aad=b""):
    """Raises ValueError if anything was modified or the key is wrong."""
    nonce = blob[:NONCE_LEN]
    tag = blob[NONCE_LEN:NONCE_LEN + TAG_LEN]
    ciphertext = blob[NONCE_LEN + TAG_LEN:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(aad)
    return cipher.decrypt_and_verify(ciphertext, tag)


def sha256_hex(data):
    """SHA-256 fingerprint of the data, as a hex string."""
    return hashlib.sha256(data).hexdigest()


def load_master_key(path):
    """Load the master key, or create it on first run."""
    if not os.path.exists(path):
        with open(path, "wb") as f:
            f.write(get_random_bytes(32))
    with open(path, "rb") as f:
        return f.read()


# ---------- digital signatures (Ed25519) ----------
def load_signing_key(path):
    """Load the server's Ed25519 signing key, or create it on first run."""
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
    if not os.path.exists(path):
        key = ed25519.Ed25519PrivateKey.generate()
        with open(path, "wb") as f:
            f.write(key.private_bytes(serialization.Encoding.PEM,
                                      serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def sign_file_record(private_key, file_id, sha256_hex_str):
    """Sign 'file_id:sha256'. Returns the signature as a hex string."""
    return private_key.sign(f"{file_id}:{sha256_hex_str}".encode()).hex()


def verify_file_record(public_key, file_id, sha256_hex_str, sig_hex):
    """True if the signature is valid, False otherwise."""
    from cryptography.exceptions import InvalidSignature
    try:
        public_key.verify(bytes.fromhex(sig_hex),
                          f"{file_id}:{sha256_hex_str}".encode())
        return True
    except (InvalidSignature, ValueError):
        return False