from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

BLOCK_SIZE = 16


def pad(data: bytes) -> bytes:
    padding_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([padding_len]) * padding_len


def unpad(data: bytes) -> bytes:
    return data[:-data[-1]]


def generate_key() -> bytes:
    return get_random_bytes(16)


def aes_encrypt(data: bytes, key: bytes) -> bytes:
    """
    AES-128 CBC
    input : bytes
    output: IV + ciphertext (bytes)
    """
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(data))
    return cipher.iv + ciphertext


def aes_decrypt(cipher_data: bytes, key: bytes) -> bytes:
    """
    AES-128 CBC
    input : IV + ciphertext
    output: plaintext bytes
    """
    iv = cipher_data[:BLOCK_SIZE]
    ciphertext = cipher_data[BLOCK_SIZE:]

    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext))
    return plaintext
