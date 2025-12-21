import sys
import os

# Proje kök dizinini Python path'e ekle
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests
import base64

from crypto.aes_lib import generate_key as generate_aes_key, aes_encrypt
from crypto.des_lib import generate_key as generate_des_key, des_encrypt
from crypto.rsa_lib import encrypt_key

AES_URL = "http://127.0.0.1:8000/receive/"
DES_URL = "http://127.0.0.1:8000/receive-des-lib/"


def main():
    print("=== CLIENT ===")
    print("1 - AES + RSA")
    print("2 - DES + RSA")

    choice = input("Algoritma seç (1/2): ").strip()
    message = input("Mesaj gir: ")

    if choice == "1":
        # ================= AES + RSA =================
        key = generate_aes_key()
        encrypted_key = encrypt_key(key)
        encrypted_message = aes_encrypt(message, key)
        url = AES_URL
        algo = "AES + RSA"

    elif choice == "2":
        # ================= DES + RSA =================
        key = generate_des_key()
        encrypted_key = encrypt_key(key)
        encrypted_message = des_encrypt(message, key)
        url = DES_URL
        algo = "DES + RSA"

    else:
        print("❌ Geçersiz seçim")
        return

    data = {
        "key": base64.b64encode(encrypted_key).decode(),
        "message": base64.b64encode(encrypted_message).decode()
    }

    response = requests.post(url, json=data)

    print(f"\n[{algo}] Sunucu cevabı:")
    print(response.text)


if __name__ == "__main__":
    main()
