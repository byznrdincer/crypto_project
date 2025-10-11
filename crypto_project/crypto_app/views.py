from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt  # ✅ ekle

# 🔐 Caesar Cipher fonksiyonu
def caesar_cipher(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base + shift) % 26 + base)
        else:
            result += char
    return result

# 🏠 Ana Sayfa
def home(request):
    return render(request, "index.html")

# 🔒 Şifreleme İşlemi
@csrf_exempt   # ✅ bu satırı ekle
def encrypt(request):
    if request.method == "POST":
        text = request.POST.get("message")
        shift = int(request.POST.get("key", 3))
        encrypted = caesar_cipher(text, shift)
        return JsonResponse({"result": encrypted})
    return JsonResponse({"error": "Invalid request"})

# 🔓 Deşifreleme İşlemi
@csrf_exempt   # ✅ bu satırı da ekle
def decrypt(request):
    if request.method == "POST":
        text = request.POST.get("message")
        shift = int(request.POST.get("key", 3))
        decrypted = caesar_cipher(text, -shift)
        return JsonResponse({"result": decrypted})
    return JsonResponse({"error": "Invalid request"})
