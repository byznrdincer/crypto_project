from Crypto.Cipher import AES
import base64

# PKCS7 padding
def pad(data):
    pad_len = 16 - len(data) % 16
    return data + chr(pad_len) * pad_len

def unpad(data):
    return data[:-ord(data[-1])]

def aes_encrypt(text, key):
    key = key.encode().ljust(16, b'0')[:16]
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted = cipher.encrypt(pad(text).encode())
    return base64.b64encode(encrypted).decode()

def aes_decrypt(ciphertext, key):
    key = key.encode().ljust(16, b'0')[:16]
    cipher = AES.new(key, AES.MODE_ECB)
    decoded = base64.b64decode(ciphertext)
    decrypted = cipher.decrypt(decoded).decode()
    return unpad(decrypted)
