import sys
import os
import requests
import base64

# Proje kök dizinini Python path'e ekle
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ===== LIBRARY BASED =====
from crypto.aes_lib import generate_key as generate_aes_key, aes_encrypt
from crypto.des_lib import generate_key as generate_des_key, des_encrypt
from crypto.rsa_lib import encrypt_key

# ===== MANUAL =====
from crypto.aes_manual import manual_aes_encrypt
from crypto.des_manual import manual_des_encrypt


# ===== SERVER ENDPOINTS =====
AES_URL = "http://127.0.0.1:8000/receive/"
DES_URL = "http://127.0.0.1:8000/receive-des-lib/"
AES_MANUAL_URL = "http://127.0.0.1:8000/receive-aes-manual/"
DES_MANUAL_URL = "http://127.0.0.1:8000/receive-des-manual/"


def main():
    print("=== CLIENT ===")
    print("1 - AES + RSA (Library)")
    print("2 - DES + RSA (Library)")
    print("3 - AES (Manual)")
    print("4 - DES (Manual)")

    choice = input("Algoritma seç (1/2/3/4): ").strip()
    message = input("Mesaj gir: ")

    # =================================================
    # AES + RSA (LIB)
    # =================================================
    if choice == "1":
        key = generate_aes_key()
        encrypted_key = encrypt_key(key)
        encrypted_message = aes_encrypt(message, key)

        data = {
            "key": base64.b64encode(encrypted_key).decode(),
            "message": base64.b64encode(encrypted_message).decode()
        }

        response = requests.post(AES_URL, json=data)
        print("\n[AES + RSA] Sunucu cevabı:")
        print(response.text)

    # =================================================
    # DES + RSA (LIB)
    # =================================================
    elif choice == "2":
        key = generate_des_key()
        encrypted_key = encrypt_key(key)
        encrypted_message = des_encrypt(message, key)

        data = {
            "key": base64.b64encode(encrypted_key).decode(),
            "message": base64.b64encode(encrypted_message).decode()
        }

        response = requests.post(DES_URL, json=data)
        print("\n[DES + RSA] Sunucu cevabı:")
        print(response.text)

    # =================================================
    # AES (MANUAL)
    # =================================================
    elif choice == "3":
        key = 23  # demo key
        cipher = manual_aes_encrypt(message, key)

        data = {
            "cipher": cipher,
            "key": key
        }

        response = requests.post(AES_MANUAL_URL, json=data)
        print("\n[AES MANUAL] Sunucu cevabı:")
        print(response.text)

    # =================================================
    # DES (MANUAL)
    # =================================================
    elif choice == "4":
        key = "SECRET"  # demo key
        cipher = manual_des_encrypt(message, key)

        data = {
            "cipher": cipher,
            "key": key
        }

        response = requests.post(DES_MANUAL_URL, json=data)
        print("\n[DES MANUAL] Sunucu cevabı:")
        print(response.text)

    else:
        print("❌ Geçersiz seçim")


if __name__ == "__main__":
    main()
