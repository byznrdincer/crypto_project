from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

BLOCK_SIZE = 16  # AES block size (16 byte)

# --------------------
# Padding helpers
# --------------------
def pad(data: bytes) -> bytes:
    padding_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([padding_len]) * padding_len

def unpad(data: bytes) -> bytes:
    return data[:-data[-1]]

# --------------------
# Key generation
# --------------------
def generate_key() -> bytes:
    return get_random_bytes(16)  # 128-bit AES key

# --------------------
# AES Encrypt
# --------------------
def aes_encrypt(message: str, key: bytes) -> bytes:
    """
    AES-128 CBC encryption
    Returns: IV + ciphertext
    """
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(message.encode("utf-8")))
    return cipher.iv + ciphertext

# --------------------
# AES Decrypt
# --------------------
def aes_decrypt(cipher_data: bytes, key: bytes) -> str:
    """
    AES-128 CBC decryption
    Expects: IV + ciphertext
    """
    iv = cipher_data[:BLOCK_SIZE]
    ciphertext = cipher_data[BLOCK_SIZE:]

    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext))
    return plaintext.decode("utf-8")
