from django.shortcuts import render

# Create your views here.
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from Crypto.Cipher import AES, DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
import base64

# ============================================================
# AES-128
# ============================================================

def pad(s):
    pad_len = 16 - len(s) % 16
    return s + chr(pad_len) * pad_len

def unpad(s):
    return s[:-ord(s[-1])]

@csrf_exempt
def aes_encrypt_library(request):
    if request.method == "POST":
        text = request.POST.get("message", "")
        key = request.POST.get("key", "mykey1234567890")

        key = key.encode().ljust(16, b'0')[:16]
        cipher = AES.new(key, AES.MODE_ECB)
        encrypted = cipher.encrypt(pad(text).encode())
        return JsonResponse({"result": base64.b64encode(encrypted).decode()})

    return JsonResponse({"error": "Invalid request"})

@csrf_exempt
def aes_decrypt_library(request):
    if request.method == "POST":
        cipher_text = request.POST.get("message", "")
        key = request.POST.get("key", "mykey1234567890")

        key = key.encode().ljust(16, b'0')[:16]
        cipher = AES.new(key, AES.MODE_ECB)
        decoded = base64.b64decode(cipher_text)
        decrypted = unpad(cipher.decrypt(decoded).decode())
        return JsonResponse({"result": decrypted})

    return JsonResponse({"error": "Invalid request"})


# ============================================================
# DES
# ============================================================

@csrf_exempt
def des_encrypt_library(request):
    if request.method == "POST":
        text = request.POST.get("message", "")
        key = request.POST.get("key", "mysecret")

        key = key.encode().ljust(8, b'0')[:8]
        cipher = DES.new(key, DES.MODE_ECB)
        padded = pad(text).encode()
        encrypted = cipher.encrypt(padded)

        return JsonResponse({"result": base64.b64encode(encrypted).decode()})

    return JsonResponse({"error": "Invalid request"})

@csrf_exempt
def des_decrypt_library(request):
    if request.method == "POST":
        cipher_text = request.POST.get("message", "")
        key = request.POST.get("key", "mysecret")

        key = key.encode().ljust(8, b'0')[:8]
        cipher = DES.new(key, DES.MODE_ECB)
        decoded = base64.b64decode(cipher_text)
        decrypted = cipher.decrypt(decoded).decode()
        return JsonResponse({"result": unpad(decrypted)})

    return JsonResponse({"error": "Invalid request"})


# ============================================================
# RSA (Gerçek – 2048bit)
# ============================================================

@csrf_exempt
def rsa_generate_keys(request):
    key = RSA.generate(2048)
    private_key = key.export_key().decode()
    public_key = key.publickey().export_key().decode()
    return JsonResponse({
        "private_key": private_key,
        "public_key": public_key
    })

@csrf_exempt
def rsa_encrypt_view(request):
    if request.method == "POST":
        message = request.POST.get("message", "")
        public_key = request.POST.get("public_key", "")

        key = RSA.import_key(public_key)
        cipher = PKCS1_OAEP.new(key)
        encrypted = cipher.encrypt(message.encode())
        return JsonResponse({"result": base64.b64encode(encrypted).decode()})

    return JsonResponse({"error": "Invalid request"})

@csrf_exempt
def rsa_decrypt_view(request):
    if request.method == "POST":
        cipher_text = request.POST.get("message", "")
        private_key = request.POST.get("private_key", "")

        key = RSA.import_key(private_key)
        cipher = PKCS1_OAEP.new(key)

        decrypted = cipher.decrypt(base64.b64decode(cipher_text))
        return JsonResponse({"result": decrypted.decode()})

    return JsonResponse({"error": "Invalid request"})
