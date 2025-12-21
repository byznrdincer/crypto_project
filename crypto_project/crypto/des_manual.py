# ==============================
# BASİTLEŞTİRİLMİŞ (MANUEL) DES
# Gerçek DES değildir, eğitim amaçlıdır
# Ama encrypt + decrypt terslenebilir (çalışır)
# ==============================

# 4-bit S-Box (DES S-box değil, demo)
S_BOX = {
    0x0: 0xE, 0x1: 0x4, 0x2: 0xD, 0x3: 0x1,
    0x4: 0x2, 0x5: 0xF, 0x6: 0xB, 0x7: 0x8,
    0x8: 0x3, 0x9: 0xA, 0xA: 0x6, 0xB: 0xC,
    0xC: 0x5, 0xD: 0x9, 0xE: 0x0, 0xF: 0x7
}
INV_S_BOX = {v: k for k, v in S_BOX.items()}

def _substitute_byte(byte: int) -> int:
    hi = (byte >> 4) & 0x0F
    lo = byte & 0x0F
    return ((S_BOX[hi] << 4) | S_BOX[lo]) & 0xFF

def _inv_substitute_byte(byte: int) -> int:
    hi = (byte >> 4) & 0x0F
    lo = byte & 0x0F
    return ((INV_S_BOX[hi] << 4) | INV_S_BOX[lo]) & 0xFF

def _rotl8(x: int, r: int) -> int:
    r %= 8
    return ((x << r) | (x >> (8 - r))) & 0xFF

def _rotr8(x: int, r: int) -> int:
    r %= 8
    return ((x >> r) | (x << (8 - r))) & 0xFF

def _feistel_round(r: int, k: int) -> int:
    # F fonksiyonu (demo): xor + sbox
    return _substitute_byte(r ^ (k & 0xFF))

def manual_des_encrypt(message: str, key: str) -> str:
    """
    Demo DES: her karakteri 8-bit al, 2-round Feistel uygula.
    Çıktı: hex string
    key: string (en az 1 char). İlk 8 byte anahtar gibi davranır.
    """
    key_bytes = key.encode("utf-8")
    if len(key_bytes) == 0:
        raise ValueError("Key boş olamaz")

    out = []
    for i, ch in enumerate(message.encode("utf-8")):
        k = key_bytes[i % len(key_bytes)]

        # 8-bit byte'ı 4-bit L/R ayır
        L = (ch >> 4) & 0x0F
        R = ch & 0x0F

        # Round 1
        f1 = _feistel_round(R, k)
        L, R = R, (L ^ (f1 & 0x0F)) & 0x0F

        # Round 2
        f2 = _feistel_round(R, _rotl8(k, 3))
        L, R = R, (L ^ (f2 & 0x0F)) & 0x0F

        c = ((L & 0x0F) << 4) | (R & 0x0F)
        out.append(f"{c:02x}")

    return "".join(out)

def manual_des_decrypt(cipher_hex: str, key: str) -> str:
    """
    manual_des_encrypt'in tersidir.
    cipher_hex: hex string (ör: '0a1bff...')
    """
    key_bytes = key.encode("utf-8")
    if len(key_bytes) == 0:
        raise ValueError("Key boş olamaz")
    if len(cipher_hex) % 2 != 0:
        raise ValueError("cipher_hex uzunluğu çift olmalı")

    cipher_bytes = bytes.fromhex(cipher_hex)

    out = bytearray()
    for i, cb in enumerate(cipher_bytes):
        k = key_bytes[i % len(key_bytes)]

        L = (cb >> 4) & 0x0F
        R = cb & 0x0F

        # Round 2'yi geri al (Feistel tersleme)
        f2 = _feistel_round(L, _rotl8(k, 3))
        L, R = (R ^ (f2 & 0x0F)) & 0x0F, L

        # Round 1'i geri al
        f1 = _feistel_round(L, k)
        L, R = (R ^ (f1 & 0x0F)) & 0x0F, L

        p = ((L & 0x0F) << 4) | (R & 0x0F)
        out.append(p)

    return out.decode("utf-8", errors="replace")
