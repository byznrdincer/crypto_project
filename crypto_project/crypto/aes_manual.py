# crypto/aes_manual.py

def manual_aes_encrypt(message: str, key: bytes) -> bytes:
    """
    XOR tabanlı MANUAL AES (DEMO)
    Encrypt: str -> bytes
    """
    message_bytes = message.encode("utf-8")
    encrypted = bytearray()

    key_len = len(key)

    for i in range(len(message_bytes)):
        encrypted.append(message_bytes[i] ^ key[i % key_len])

    return bytes(encrypted)


def manual_aes_decrypt(cipher_bytes: bytes, key: bytes) -> bytes:
    """
    XOR tabanlı MANUAL AES (DEMO)
    Decrypt: bytes -> bytes
    """
    decrypted = bytearray()
    key_len = len(key)

    for i in range(len(cipher_bytes)):
        decrypted.append(cipher_bytes[i] ^ key[i % key_len])

    return bytes(decrypted)
