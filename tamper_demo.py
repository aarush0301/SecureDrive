from crypto_utils import encrypt_bytes, decrypt_bytes, new_data_key

key = new_data_key()
original = b"Quarterly report - CONFIDENTIAL " * 100
blob = bytearray(encrypt_bytes(key, original))

print("1. Untouched file decrypts correctly:",
      decrypt_bytes(key, bytes(blob)) == original)

blob[40] ^= 0x01          # attacker flips a single bit

try:
    decrypt_bytes(key, bytes(blob))
    print("2. Tampered file decrypted  <-- should never print")
except ValueError:
    print("2. One bit changed -> decryption REJECTED (integrity violation)")