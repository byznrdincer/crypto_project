from Crypto.Cipher import DES
import base64

def pad(data):
    pad_len = 8 - len(data) % 8
    return data + chr(pad_len) * pad_len

def unpad(data):
    return data[:-ord(data[-1])]

def des_encrypt(text, key):
    key = key.encode().ljust(8, b'0')[:8]
    cipher = DES.new(key, DES.MODE_ECB)
    encrypted = cipher.encrypt(pad(text).encode())
    return base64.b64encode(encrypted).decode()

def des_decrypt(ciphertext, key):
    key = key.encode().ljust(8, b'0')[:8]
    cipher = DES.new(key, DES.MODE_ECB)
    decrypted = cipher.decrypt(base64.b64decode(ciphertext)).decode()
    return unpad(decrypted)
