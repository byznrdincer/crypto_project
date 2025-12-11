# Mini AES (Eğitim İçin)

SBOX = { 
    chr(i): chr((i * 7 + 3) % 256) for i in range(256)
}

def aes_manual_encrypt(text, key):
    x1 = "".join(chr(ord(text[i]) ^ ord(key[i % len(key)])) for i in range(len(text)))
    x2 = "".join(SBOX.get(c, c) for c in x1)
    x3 = x2[1:] + x2[0]
    cipher = "".join(chr(ord(x3[i]) ^ ord(key[i % len(key)])) for i in range(len(x3)))
    return cipher.encode().hex()

def aes_manual_decrypt(cipher_hex, key):
    cipher = bytes.fromhex(cipher_hex).decode(errors="ignore")
    x3 = "".join(chr(ord(cipher[i]) ^ ord(key[i % len(key)])) for i in range(len(cipher)))
    x2 = x3[-1] + x3[:-1]
    inv = {v: k for k, v in SBOX.items()}
    x1 = "".join(inv.get(c, c) for c in x2)
    text = "".join(chr(ord(x1[i]) ^ ord(key[i % len(key)])) for i in range(len(x1)))
    return text
