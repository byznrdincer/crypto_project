from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

# ============================================================
# 🔐 Caesar Cipher
# ============================================================
def caesar_cipher(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base + shift) % 26 + base)
        else:
            result += char
    return result


# ============================================================
# 🔐 Vigenère Cipher
# ============================================================
def vigenere_cipher(text, key, decrypt=False):
    result = ""
    key = key.lower()
    key_index = 0

    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            shift = ord(key[key_index % len(key)]) - ord('a')
            if decrypt:
                shift = -shift
            result += chr((ord(char) - base + shift) % 26 + base)
            key_index += 1
        else:
            result += char

    return result


# ============================================================
# 🌐 VIEWS
# ============================================================

def home(request):
    return render(request, "index.html")


# 🧩 Caesar Cipher
@csrf_exempt
def encrypt(request):
    if request.method == "POST":
        text = request.POST.get("message")
        shift = int(request.POST.get("key", 3))
        encrypted = caesar_cipher(text, shift)
        return JsonResponse({"result": encrypted})
    return JsonResponse({"error": "Invalid request"})


@csrf_exempt
def decrypt(request):
    if request.method == "POST":
        text = request.POST.get("message")
        shift = int(request.POST.get("key", 3))
        decrypted = caesar_cipher(text, -shift)
        return JsonResponse({"result": decrypted})
    return JsonResponse({"error": "Invalid request"})


# 🧩 Vigenère Cipher (Yeni eklendi)
@csrf_exempt
def vigenere_encrypt(request):
    if request.method == "POST":
        text = request.POST.get("message", "")
        key = request.POST.get("key", "key")  # varsayılan anahtar
        encrypted = vigenere_cipher(text, key, decrypt=False)
        return JsonResponse({"result": encrypted})
    return JsonResponse({"error": "Invalid request"})


@csrf_exempt
def vigenere_decrypt(request):
    if request.method == "POST":
        text = request.POST.get("message", "")
        key = request.POST.get("key", "key")
        decrypted = vigenere_cipher(text, key, decrypt=True)
        return JsonResponse({"result": decrypted})
    return JsonResponse({"error": "Invalid request"})
