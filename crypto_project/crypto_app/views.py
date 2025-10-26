from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import numpy as np

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

# ============================================================
# 🔐 Columnar Transposition Cipher
# ============================================================
def columnar_transposition_cipher(text, key, decrypt=False):
    text = text.replace(" ", "")
    key_order = sorted(list(key))
    key_len = len(key)
    num_rows = -(-len(text) // key_len)  # yukarı yuvarla

    if not decrypt:
        # Matris oluştur
        matrix = [[''] * key_len for _ in range(num_rows)]
        idx = 0
        for r in range(num_rows):
            for c in range(key_len):
                if idx < len(text):
                    matrix[r][c] = text[idx]
                    idx += 1
        # Anahtar sırasına göre sütunları oku
        result = ''
        for k in key_order:
            col = key.index(k)
            for r in range(num_rows):
                if matrix[r][col]:
                    result += matrix[r][col]
        return result
    else:
        # Decrypt
        num_full_cols = len(text) % key_len
        num_rows = len(text) // key_len
        extra = 0 if num_full_cols == 0 else 1
        num_rows += extra
        col_lengths = [num_rows if key_order.index(k) < num_full_cols else num_rows - 1 for k in key_order]

        # Doldur
        columns = {}
        idx = 0
        for k in key_order:
            l = col_lengths[key_order.index(k)]
            columns[k] = list(text[idx:idx + l])
            idx += l

        result = ''
        for i in range(max(col_lengths)):
            for k in key:
                if i < len(columns[k]):
                    result += columns[k][i]
        return result

# ============================================================
# 🔐 Hill Cipher (2x2 Matris)
# ============================================================


def hill_cipher(text, key_matrix, decrypt=False):
    text = text.replace(" ", "").upper()
    m = len(key_matrix)
    while len(text) % m != 0:
        text += 'X'  # padding
    result = ""

    key_matrix = np.array(key_matrix)
    if decrypt:
        det = int(round(np.linalg.det(key_matrix)))
        det_inv = pow(int(det % 26), -1, 26)
        adjugate = np.round(det * np.linalg.inv(key_matrix)).astype(int) % 26
        key_matrix = (det_inv * adjugate) % 26

    for i in range(0, len(text), m):
        block = [ord(c) - 65 for c in text[i:i + m]]
        encrypted = np.dot(key_matrix, block) % 26
        result += ''.join(chr(int(x) + 65) for x in encrypted)

    return result
# ============================================================
# 🔐 Vernam Cipher (One-Time Pad)
# ============================================================
def vernam_cipher(text, key, decrypt=False):
    result = ""
    key = key.upper()
    text = text.upper()

    for i in range(len(text)):
        if text[i].isalpha():
            t = ord(text[i]) - 65
            k = ord(key[i % len(key)]) - 65
            val = (t - k) % 26 if decrypt else (t + k) % 26
            result += chr(val + 65)
        else:
            result += text[i]
    return result
# 🧩 Columnar Transposition Cipher
@csrf_exempt
def columnar_encrypt(request):
    if request.method == "POST":
        text = request.POST.get("message", "")
        key = request.POST.get("key", "KEY")
        result = columnar_transposition_cipher(text, key, decrypt=False)
        return JsonResponse({"result": result})
    return JsonResponse({"error": "Invalid request"})

@csrf_exempt
def columnar_decrypt(request):
    if request.method == "POST":
        text = request.POST.get("message", "")
        key = request.POST.get("key", "KEY")
        result = columnar_transposition_cipher(text, key, decrypt=True)
        return JsonResponse({"result": result})
    return JsonResponse({"error": "Invalid request"})


# 🧩 Hill Cipher
@csrf_exempt
def hill_encrypt(request):
    if request.method == "POST":
        text = request.POST.get("message", "")
        key_matrix = [[3, 3], [2, 5]]  # örnek 2x2 anahtar matrisi
        result = hill_cipher(text, key_matrix, decrypt=False)
        return JsonResponse({"result": result})
    return JsonResponse({"error": "Invalid request"})

@csrf_exempt
def hill_decrypt(request):
    if request.method == "POST":
        text = request.POST.get("message", "")
        key_matrix = [[3, 3], [2, 5]]
        result = hill_cipher(text, key_matrix, decrypt=True)
        return JsonResponse({"result": result})
    return JsonResponse({"error": "Invalid request"})


# 🧩 Vernam Cipher
@csrf_exempt
def vernam_encrypt(request):
    if request.method == "POST":
        text = request.POST.get("message", "")
        key = request.POST.get("key", "KEY")
        result = vernam_cipher(text, key, decrypt=False)
        return JsonResponse({"result": result})
    return JsonResponse({"error": "Invalid request"})

@csrf_exempt
def vernam_decrypt(request):
    if request.method == "POST":
        text = request.POST.get("message", "")
        key = request.POST.get("key", "KEY")
        result = vernam_cipher(text, key, decrypt=True)
        return JsonResponse({"result": result})
    return JsonResponse({"error": "Invalid request"})
