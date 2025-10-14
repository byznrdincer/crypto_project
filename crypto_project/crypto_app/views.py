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
# 🔐 Affine Cipher
# ============================================================
def affine_cipher(text, a, b, decrypt=False):
    result = ""
    m = 26  # alfabe uzunluğu

    # gcd(a,26) = 1 olmalı (tersi olabilmesi için)
    def mod_inverse(a, m):
        for x in range(1, m):
            if (a * x) % m == 1:
                return x
        return None

    a_inv = mod_inverse(a, m)

    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            x = ord(char) - base
            if decrypt:
                result += chr(((a_inv * (x - b)) % m) + base)
            else:
                result += chr(((a * x + b) % m) + base)
        else:
            result += char

    return result


# ============================================================
# 🔐 Substitution Cipher
# ============================================================
def substitution_cipher(text, key, decrypt=False):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    key = key.upper()

    if decrypt:
        table = str.maketrans(key, alphabet)
    else:
        table = str.maketrans(alphabet, key)

    return text.upper().translate(table)


# ============================================================
# 🔐 Rail Fence Cipher
# ============================================================
def rail_fence_cipher(text, rails, decrypt=False):
    if rails == 1:
        return text

    text = text.replace(" ", "")
    if not decrypt:
        fence = [[] for _ in range(rails)]
        rail = 0
        var = 1

        for char in text:
            fence[rail].append(char)
            rail += var
            if rail == 0 or rail == rails - 1:
                var = -var

        return ''.join([''.join(row) for row in fence])
    else:
        # çözümleme
        pattern = list(range(rails)) + list(range(rails - 2, 0, -1))
        pattern = (pattern * ((len(text) // len(pattern)) + 1))[:len(text)]
        pos = sorted(range(len(text)), key=lambda i: pattern[i])
        result = [''] * len(text)
        i = 0
        for p in pos:
            result[p] = text[i]
            i += 1
        return ''.join(result)


# ============================================================
# 🌐 VIEWS
# ============================================================
def home(request):
    return render(request, "index.html")


# 🧩 Caesar Cipher
@csrf_exempt
def encrypt(request):
    if request.method == "POST":
        text = request.POST.get("message", "")
        shift = int(request.POST.get("key", 3))
        encrypted = caesar_cipher(text, shift)
        return JsonResponse({"result": encrypted})
    return JsonResponse({"error": "Invalid request"})


@csrf_exempt
def decrypt(request):
    if request.method == "POST":
        text = request.POST.get("message", "")
        shift = int(request.POST.get("key", 3))
        decrypted = caesar_cipher(text, -shift)
        return JsonResponse({"result": decrypted})
    return JsonResponse({"error": "Invalid request"})


# 🧩 Vigenère Cipher
@csrf_exempt
def vigenere_encrypt(request):
    if request.method == "POST":
        text = request.POST.get("message", "")
        key = request.POST.get("key", "key")
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


# 🧩 Affine Cipher
@csrf_exempt
def affine_encrypt(request):
    if request.method == "POST":
        text = request.POST.get("message", "")
        a = int(request.POST.get("a", 5))
        b = int(request.POST.get("b", 8))
        encrypted = affine_cipher(text, a, b, decrypt=False)
        return JsonResponse({"result": encrypted})
    return JsonResponse({"error": "Invalid request"})


@csrf_exempt
def affine_decrypt(request):
    if request.method == "POST":
        text = request.POST.get("message", "")
        a = int(request.POST.get("a", 5))
        b = int(request.POST.get("b", 8))
        decrypted = affine_cipher(text, a, b, decrypt=True)
        return JsonResponse({"result": decrypted})
    return JsonResponse({"error": "Invalid request"})


# 🧩 Substitution Cipher
@csrf_exempt
def substitution_encrypt(request):
    if request.method == "POST":
        text = request.POST.get("message", "")
        key = request.POST.get("key", "QWERTYUIOPASDFGHJKLZXCVBNM")
        encrypted = substitution_cipher(text, key, decrypt=False)
        return JsonResponse({"result": encrypted})
    return JsonResponse({"error": "Invalid request"})


@csrf_exempt
def substitution_decrypt(request):
    if request.method == "POST":
        text = request.POST.get("message", "")
        key = request.POST.get("key", "QWERTYUIOPASDFGHJKLZXCVBNM")
        decrypted = substitution_cipher(text, key, decrypt=True)
        return JsonResponse({"result": decrypted})
    return JsonResponse({"error": "Invalid request"})


# 🧩 Rail Fence Cipher
@csrf_exempt
def railfence_encrypt(request):
    if request.method == "POST":
        text = request.POST.get("message", "")
        rails = int(request.POST.get("key", 2))
        encrypted = rail_fence_cipher(text, rails, decrypt=False)
        return JsonResponse({"result": encrypted})
    return JsonResponse({"error": "Invalid request"})


@csrf_exempt
def railfence_decrypt(request):
    if request.method == "POST":
        text = request.POST.get("message", "")
        rails = int(request.POST.get("key", 2))
        decrypted = rail_fence_cipher(text, rails, decrypt=True)
        return JsonResponse({"result": decrypted})
    return JsonResponse({"error": "Invalid request"})
