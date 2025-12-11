# Mini DES (Eğitim İçin)

def simple_permute(bits):
    return bits[::-1]

def text_to_bits(text):
    return ''.join(format(ord(c), '08b') for c in text)

def bits_to_text(bits):
    chars = [bits[i:i+8] for i in range(0, len(bits), 8)]
    return ''.join(chr(int(c, 2)) for c in chars)

def des_manual_encrypt(text, key):
    bits = text_to_bits(text)
    perm = simple_permute(bits)
    return perm

def des_manual_decrypt(bits, key):
    return bits_to_text(simple_permute(bits))
