# BASİTLEŞTİRİLMİŞ (MANUEL) AES MANTIĞI
# Gerçek AES değildir, eğitim amaçlıdır

S_BOX = {
    0x0: 0x9, 0x1: 0x4, 0x2: 0xA, 0x3: 0xB,
    0x4: 0xD, 0x5: 0x1, 0x6: 0x8, 0x7: 0x5,
    0x8: 0x6, 0x9: 0x2, 0xA: 0x0, 0xB: 0x3,
    0xC: 0xC, 0xD: 0xE, 0xE: 0xF, 0xF: 0x7
}

def substitute(byte: int) -> int:
    high = byte >> 4
    low = byte & 0x0F
    return (S_BOX[high] << 4) | S_BOX[low]

def manual_aes_encrypt(message: str, key: int) -> list:
    encrypted = []
    for ch in message:
        x = ord(ch) ^ key          # XOR (AddRoundKey)
        x = substitute(x)          # SubBytes
        encrypted.append(x)
    return encrypted

def manual_aes_decrypt(cipher: list, key: int) -> str:
    decrypted = ""
    for x in cipher:
        x = substitute(x)          # basit tersleme yok, demo
        x = x ^ key
        decrypted += chr(x)
    return decrypted
