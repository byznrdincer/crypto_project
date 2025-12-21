from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes

BLOCK_SIZE = 8  # DES block size (8 byte)

def pad(data: bytes) -> bytes:
    padding_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([padding_len]) * padding_len

def unpad(data: bytes) -> bytes:
    return data[:-data[-1]]

def generate_key() -> bytes:
    return get_random_bytes(8)  # 64-bit DES key

def des_encrypt(message: str, key: bytes) -> bytes:
    cipher = DES.new(key, DES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(message.encode()))
    return cipher.iv + ciphertext

def des_decrypt(cipher_data: bytes, key: bytes) -> str:
    iv = cipher_data[:BLOCK_SIZE]
    ciphertext = cipher_data[BLOCK_SIZE:]
    cipher = DES.new(key, DES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext))
    return plaintext.decode()
