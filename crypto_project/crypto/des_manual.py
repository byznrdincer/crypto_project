

def manual_des_encrypt(message: str, key: bytes) -> bytes:
    """
    MANUAL DES ENCRYPT (XOR demo)
    - input : message (str)
    - key   : bytes (8 byte)
    - output: bytes
    """

    # message → bytes
    msg_bytes = message.encode("utf-8")

    encrypted = bytearray()
    key_len = len(key)

    for i, b in enumerate(msg_bytes):
        encrypted.append(b ^ key[i % key_len])

    return bytes(encrypted)


def manual_des_decrypt(cipher_bytes: bytes, key: bytes) -> bytes:
    """
    MANUAL DES DECRYPT (XOR demo)
    - input : cipher_bytes (bytes)
    - key   : bytes (8 byte)
    - output: bytes
    """

    decrypted = bytearray()
    key_len = len(key)

    for i, b in enumerate(cipher_bytes):
        decrypted.append(b ^ key[i % key_len])

    return bytes(decrypted)
