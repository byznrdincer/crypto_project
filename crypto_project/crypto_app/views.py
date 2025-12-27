import os
from django.http import JsonResponse
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
import json
import base64

import numpy as np

from crypto.rsa_lib import decrypt_key, encrypt_key
from crypto.aes_lib import aes_decrypt, aes_encrypt, generate_key
from crypto.des_lib import des_decrypt, des_encrypt


from crypto.aes_manual import manual_aes_decrypt, manual_aes_encrypt
from crypto.des_manual import manual_des_decrypt, manual_des_encrypt




def caesar_cipher(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base + shift) % 26 + base)
        else:
            result += char
    return result



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


def affine_cipher(text, a, b, decrypt=False):
    result = ""
    m = 26  # alfabe uzunluğu

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


def substitution_cipher(text, key, decrypt=False):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    key = key.upper()

    if decrypt:
        table = str.maketrans(key, alphabet)
    else:
        table = str.maketrans(alphabet, key)

    return text.upper().translate(table)


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


#  Substitution Cipher
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


#  Rail Fence Cipher
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
#  Columnar Transposition Cipher
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


#  Hill Cipher
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


#  Vernam Cipher
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



@csrf_exempt
def receive_message(request):
    if request.method != "POST":
        return JsonResponse({"error": "POST only"}, status=400)

    try:
        body = json.loads(request.body)

        # 1️ Plain text mesaj
        plaintext = body.get("message", "").encode("utf-8")

        # 2️ AES key üret
        aes_key = generate_key()  # senin aes_lib içindeki fonksiyon

        # 3️ AES ile şifrele
        encrypted_message = aes_encrypt(plaintext, aes_key)


        # 4️ AES key’i RSA ile şifrele
        encrypted_key = encrypt_key(aes_key)

        return JsonResponse({
            "algorithm": "AES + RSA (LIB)",
            "ciphertext": base64.b64encode(encrypted_message).decode(),
            "encrypted_key": base64.b64encode(encrypted_key).decode()
        })

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)


@csrf_exempt
def receive_des_lib(request):
    if request.method != "POST":
        return JsonResponse({"error": "POST only"}, status=400)

    try:
        body = json.loads(request.body)

        
        plaintext = body.get("message", "")  # str

        des_key = os.urandom(8)

        encrypted_message = des_encrypt(plaintext, des_key)
        encrypted_key = encrypt_key(des_key)

        return JsonResponse({
            "algorithm": "DES + RSA (LIB)",
            "ciphertext": base64.b64encode(encrypted_message).decode(),
            "encrypted_key": base64.b64encode(encrypted_key).decode()
        })

    except Exception as e:
        print("❌ DES ERROR:", e)
        return JsonResponse({"error": str(e)}, status=500)
@csrf_exempt
def receive_aes_manual(request):
    if request.method != "POST":
        return JsonResponse({"error": "POST only"}, status=400)

    try:
        # ================= FILE MODE =================
        if "file" in request.FILES:
            message, error = read_text_file_only(request)
            if error:
                return error
            key_str = request.POST.get("key", "")

        # ================= TEXT MODE =================
        else:
            body = json.loads(request.body)
            message = body.get("message", "")
            key_str = body.get("key", "")

        if not message or not key_str:
            return JsonResponse(
                {"error": "message/file and key are required"},
                status=400
            )

        key = key_str.encode("utf-8")

        if len(key) not in (16, 24, 32):
            return JsonResponse(
                {"error": "AES key must be 16, 24 or 32 bytes"},
                status=400
            )

        cipher_bytes = manual_aes_encrypt(message, key)
        cipher_b64 = base64.b64encode(cipher_bytes).decode("utf-8")

        return JsonResponse({
            "algorithm": "AES (MANUAL)",
            "mode": "file" if "file" in request.FILES else "text",
            "ciphertext": cipher_b64
        })

    except Exception as e:
        print("AES MANUAL ENCRYPT ERROR:", e)
        return JsonResponse(
            {"error": "AES manual encrypt failed"},
            status=500
        )      
@csrf_exempt
def receive_aes_manual_decrypt(request):
    if request.method != "POST":
        return JsonResponse({"error": "POST only"}, status=400)

    try:
        body = json.loads(request.body)
        cipher_b64 = body.get("cipher", "")
        key_str = body.get("key", "")

        if not cipher_b64 or not key_str:
            return JsonResponse(
                {"error": "cipher and key are required"},
                status=400
            )

        key = key_str.encode("utf-8")

        if len(key) not in (16, 24, 32):
            return JsonResponse(
                {"error": "AES key must be 16, 24 or 32 bytes"},
                status=400
            )

        cipher_bytes = base64.b64decode(cipher_b64)
        plaintext_bytes = manual_aes_decrypt(cipher_bytes, key)

        return JsonResponse({
            "algorithm": "AES (MANUAL)",
            "plaintext": plaintext_bytes.decode("utf-8", errors="replace")
        })

    except Exception as e:
        print("❌ AES MANUAL DECRYPT ERROR:", e)
        return JsonResponse(
            {"error": "AES manual decrypt failed"},
            status=500
        )

@csrf_exempt
def receive_des_manual(request):
    if request.method != "POST":
        return JsonResponse({"error": "POST only"}, status=400)

    try:
        # ================= FILE MODE =================
        if "file" in request.FILES:
            message, error = read_text_file_only(request)
            if error:
                return error
            key_str = request.POST.get("key", "")

        # ================= TEXT MODE =================
        else:
            body = json.loads(request.body)
            message = body.get("message", "")
            key_str = body.get("key", "")

        if not message or not key_str:
            return JsonResponse(
                {"error": "message/file and key are required"},
                status=400
            )

        key = key_str.encode("utf-8")

        if len(key) != 8:
            return JsonResponse(
                {"error": "DES key must be exactly 8 bytes"},
                status=400
            )

        cipher_bytes = manual_des_encrypt(message, key)
        cipher_b64 = base64.b64encode(cipher_bytes).decode("utf-8")

        return JsonResponse({
            "algorithm": "DES (MANUAL)",
            "mode": "file" if "file" in request.FILES else "text",
            "ciphertext": cipher_b64
        })

    except Exception as e:
        print("❌ DES MANUAL ENCRYPT ERROR:", e)
        return JsonResponse(
            {"error": "DES manual encrypt failed"},
            status=500 )  
        


@csrf_exempt
def receive_des_manual_decrypt(request):
    if request.method != "POST":
        return JsonResponse({"error": "POST only"}, status=400)

    try:
        # ================= FILE MODE =================
        if "file" in request.FILES:
            cipher_b64, error = read_text_file_only(request)
            if error:
                return error
            key_str = request.POST.get("key", "")

        # ================= TEXT MODE =================
        else:
            body = json.loads(request.body)
            cipher_b64 = body.get("cipher", "")
            key_str = body.get("key", "")

        if not cipher_b64 or not key_str:
            return JsonResponse(
                {"error": "cipher/file and key are required"},
                status=400
            )

        key = key_str.encode("utf-8")

        if len(key) != 8:
            return JsonResponse(
                {"error": "DES key must be exactly 8 bytes"},
                status=400
            )

        cipher_bytes = base64.b64decode(cipher_b64)
        plaintext_bytes = manual_des_decrypt(cipher_bytes, key)
        plaintext = plaintext_bytes.decode("utf-8", errors="replace")

        return JsonResponse({
            "algorithm": "DES (MANUAL)",
            "mode": "file" if "file" in request.FILES else "text",
            "plaintext": plaintext
        })

    except Exception as e:
        print("❌ DES MANUAL DECRYPT ERROR:", e)
        return JsonResponse(
            {"error": "DES manual decrypt failed"},
            status=500
        )
 
@csrf_exempt
def encrypt_file_aes_rsa(request):
    if request.method != "POST":
        return JsonResponse({"error": "POST only"}, status=400)

    if "file" not in request.FILES:
        return JsonResponse({"error": "file is required"}, status=400)

    try:
        uploaded_file = request.FILES["file"]

        # 🔥 DOSYA BYTE OLARAK OKUNUR (ASLA decode YOK)
        file_bytes = uploaded_file.read()

        # 1️⃣ AES key üret (bytes)
        aes_key = generate_key()

        # 2️⃣ DOSYAYI AES İLE ŞİFRELE (bytes → bytes)
        encrypted_data = aes_encrypt(file_bytes, aes_key)

        # 3️⃣ AES key’i RSA ile şifrele
        encrypted_key = encrypt_key(aes_key)

        return JsonResponse({
            "filename": uploaded_file.name,
            "algorithm": "AES + RSA",
            "ciphertext": base64.b64encode(encrypted_data).decode("utf-8"),
            "encrypted_key": base64.b64encode(encrypted_key).decode("utf-8")
        })

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

@csrf_exempt
def decrypt_file_aes_rsa(request):
    if request.method != "POST":
        return JsonResponse({"error": "POST only"}, status=400)

    try:
        body = json.loads(request.body)

        cipher_b64 = body.get("ciphertext")
        encrypted_key_b64 = body.get("encrypted_key")

        if not cipher_b64 or not encrypted_key_b64:
            return JsonResponse({"error": "ciphertext and encrypted_key required"}, status=400)

        encrypted_data = base64.b64decode(cipher_b64)
        encrypted_key = base64.b64decode(encrypted_key_b64)

        # 1️⃣ AES key’i RSA ile çöz
        aes_key = decrypt_key(encrypted_key)

        # 2️⃣ Dosya içeriğini AES ile çöz
        plaintext = aes_decrypt(encrypted_data, aes_key)

        return JsonResponse({
            "plaintext": plaintext
        })

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

@csrf_exempt
def encrypt_file_des_rsa(request):
    if request.method != "POST":
        return JsonResponse({"error": "POST only"}, status=400)

    if "file" not in request.FILES:
        return JsonResponse({"error": "file is required"}, status=400)

    try:
        uploaded_file = request.FILES["file"]
        file_bytes = uploaded_file.read()

        # 1️⃣ DES key (8 byte)
        des_key = os.urandom(8)

        # 2️⃣ DES ile dosya şifrele
        encrypted_data = des_encrypt(
            file_bytes.decode("utf-8", errors="ignore"),
            des_key
        )

        # 3️⃣ DES key’i RSA ile şifrele
        encrypted_key = encrypt_key(des_key)

        return JsonResponse({
            "filename": uploaded_file.name,
            "algorithm": "DES + RSA",
            "ciphertext": base64.b64encode(encrypted_data).decode(),
            "encrypted_key": base64.b64encode(encrypted_key).decode()
        })

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)
@csrf_exempt
def decrypt_file_des_rsa(request):
    if request.method != "POST":
        return JsonResponse({"error": "POST only"}, status=400)

    try:
        body = json.loads(request.body)

        cipher_b64 = body.get("ciphertext")
        encrypted_key_b64 = body.get("encrypted_key")

        if not cipher_b64 or not encrypted_key_b64:
            return JsonResponse(
                {"error": "ciphertext and encrypted_key required"},
                status=400
            )

        # base64 → bytes
        encrypted_data = base64.b64decode(cipher_b64)
        encrypted_key = base64.b64decode(encrypted_key_b64)

        # RSA → DES key
        des_key = decrypt_key(encrypted_key)

        # DES → plaintext
        plaintext = des_decrypt(encrypted_data, des_key)

        return JsonResponse({
            "algorithm": "DES + RSA",
            "plaintext": plaintext
        })

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)
def read_text_file_only(request):
    if "file" not in request.FILES:
        return None, JsonResponse({"error": "file is required"}, status=400)

    uploaded_file = request.FILES["file"]

    if not uploaded_file.name.lower().endswith(".txt"):
        return None, JsonResponse(
            {"error": "Only .txt files are supported"},
            status=400
        )

    try:
        content = uploaded_file.read().decode("utf-8")
        return content, None
    except UnicodeDecodeError:
        return None, JsonResponse(
            {"error": "File must be UTF-8 encoded text"},
            status=400
        )
@csrf_exempt
def caesar_encrypt_file(request):
    if request.method != "POST":
        return JsonResponse({"error": "POST only"}, status=400)

    text, error = read_text_file_only(request)
    if error:
        return error

    shift = int(request.POST.get("key", 3))
    encrypted = caesar_cipher(text, shift)

    return JsonResponse({
        "algorithm": "Caesar (TXT FILE)",
        "ciphertext": encrypted
    })


@csrf_exempt
def caesar_decrypt_file(request):
    if request.method != "POST":
        return JsonResponse({"error": "POST only"}, status=400)

    text, error = read_text_file_only(request)
    if error:
        return error

    shift = int(request.POST.get("key", 3))
    decrypted = caesar_cipher(text, -shift)

    return JsonResponse({
        "algorithm": "Caesar (TXT FILE)",
        "plaintext": decrypted
    })
@csrf_exempt
def vigenere_encrypt_file(request):
    if request.method != "POST":
        return JsonResponse({"error": "POST only"}, status=400)

    text, error = read_text_file_only(request)
    if error:
        return error

    key = request.POST.get("key", "")
    encrypted = vigenere_cipher(text, key)

    return JsonResponse({
        "algorithm": "Vigenere (TXT FILE)",
        "ciphertext": encrypted
    })


@csrf_exempt
def vigenere_decrypt_file(request):
    if request.method != "POST":
        return JsonResponse({"error": "POST only"}, status=400)

    text, error = read_text_file_only(request)
    if error:
        return error

    key = request.POST.get("key", "")
    decrypted = vigenere_cipher(text, key, decrypt=True)

    return JsonResponse({
        "algorithm": "Vigenere (TXT FILE)",
        "plaintext": decrypted
    })
@csrf_exempt
def vigenere_encrypt_file(request):
    if request.method != "POST":
        return JsonResponse({"error": "POST only"}, status=400)

    text, error = read_text_file_only(request)
    if error:
        return error

    key = request.POST.get("key", "")
    encrypted = vigenere_cipher(text, key)

    return JsonResponse({
        "algorithm": "Vigenere (TXT FILE)",
        "ciphertext": encrypted
    })


@csrf_exempt
def vigenere_decrypt_file(request):
    if request.method != "POST":
        return JsonResponse({"error": "POST only"}, status=400)

    text, error = read_text_file_only(request)
    if error:
        return error

    key = request.POST.get("key", "")
    decrypted = vigenere_cipher(text, key, decrypt=True)

    return JsonResponse({
        "algorithm": "Vigenere (TXT FILE)",
        "plaintext": decrypted
    })
@csrf_exempt
def affine_encrypt_file(request):
    if request.method != "POST":
        return JsonResponse({"error": "POST only"}, status=400)

    text, error = read_text_file_only(request)
    if error:
        return error

    a = int(request.POST.get("a", 5))
    b = int(request.POST.get("b", 8))

    encrypted = affine_cipher(text, a, b)

    return JsonResponse({
        "algorithm": "Affine (TXT FILE)",
        "ciphertext": encrypted
    })


@csrf_exempt
def affine_decrypt_file(request):
    if request.method != "POST":
        return JsonResponse({"error": "POST only"}, status=400)

    text, error = read_text_file_only(request)
    if error:
        return error

    a = int(request.POST.get("a", 5))
    b = int(request.POST.get("b", 8))

    decrypted = affine_cipher(text, a, b, decrypt=True)

    return JsonResponse({
        "algorithm": "Affine (TXT FILE)",
        "plaintext": decrypted
    })
@csrf_exempt
def substitution_encrypt_file(request):
    if request.method != "POST":
        return JsonResponse({"error": "POST only"}, status=400)

    text, error = read_text_file_only(request)
    if error:
        return error

    key = request.POST.get("key")
    encrypted = substitution_cipher(text, key)

    return JsonResponse({
        "algorithm": "Substitution (TXT FILE)",
        "ciphertext": encrypted
    })


@csrf_exempt
def substitution_decrypt_file(request):
    if request.method != "POST":
        return JsonResponse({"error": "POST only"}, status=400)

    text, error = read_text_file_only(request)
    if error:
        return error

    key = request.POST.get("key")
    decrypted = substitution_cipher(text, key, decrypt=True)

    return JsonResponse({
        "algorithm": "Substitution (TXT FILE)",
        "plaintext": decrypted
    })
@csrf_exempt
def railfence_encrypt_file(request):
    if request.method != "POST":
        return JsonResponse({"error": "POST only"}, status=400)

    text, error = read_text_file_only(request)
    if error:
        return error

    rails = int(request.POST.get("key", 2))
    encrypted = rail_fence_cipher(text, rails)

    return JsonResponse({
        "algorithm": "Rail Fence (TXT FILE)",
        "ciphertext": encrypted
    })


@csrf_exempt
def railfence_decrypt_file(request):
    if request.method != "POST":
        return JsonResponse({"error": "POST only"}, status=400)

    text, error = read_text_file_only(request)
    if error:
        return error

    rails = int(request.POST.get("key", 2))
    decrypted = rail_fence_cipher(text, rails, decrypt=True)

    return JsonResponse({
        "algorithm": "Rail Fence (TXT FILE)",
        "plaintext": decrypted
    })
def decrypt_page(request):
    return render(request, "decrypt_server.html")

@csrf_exempt
def decrypt_aes_rsa_text(request):
    if request.method != "POST":
        return JsonResponse({"error": "POST only"}, status=400)

    try:
        body = json.loads(request.body)

        cipher_b64 = body.get("ciphertext")
        encrypted_key_b64 = body.get("encrypted_key")

        if not cipher_b64 or not encrypted_key_b64:
            return JsonResponse(
                {"error": "ciphertext and encrypted_key required"},
                status=400
            )

        # base64 → bytes
        cipher_bytes = base64.b64decode(cipher_b64)
        encrypted_key = base64.b64decode(encrypted_key_b64)

        # 🔓 RSA → AES key
        aes_key = decrypt_key(encrypted_key)

        # 🔓 AES → plaintext
        plaintext_bytes = aes_decrypt(cipher_bytes, aes_key)
        plaintext = plaintext_bytes.decode("utf-8", errors="replace")

        return JsonResponse({
            "algorithm": "AES + RSA (LIB)",
            "plaintext": plaintext
        })

    except Exception as e:
        print("❌ AES RSA TEXT DECRYPT ERROR:", e)
        return JsonResponse({"error": str(e)}, status=500)
@csrf_exempt
def decrypt_des_rsa_text(request):
    if request.method != "POST":
        return JsonResponse({"error": "POST only"}, status=400)

    try:
        body = json.loads(request.body)

        cipher_b64 = body.get("ciphertext")
        encrypted_key_b64 = body.get("encrypted_key")

        if not cipher_b64 or not encrypted_key_b64:
            return JsonResponse(
                {"error": "ciphertext and encrypted_key required"},
                status=400
            )

        # base64 → bytes
        cipher_bytes = base64.b64decode(cipher_b64)
        encrypted_key = base64.b64decode(encrypted_key_b64)

        # 🔑 RSA → DES key
        des_key = decrypt_key(encrypted_key)

        # 🔓 DES → plaintext
        plaintext = des_decrypt(cipher_bytes, des_key)

        return JsonResponse({
            "algorithm": "DES + RSA (LIB)",
            "plaintext": plaintext
        })

    except Exception as e:
        print("❌ DES RSA TEXT DECRYPT ERROR:", e)
        return JsonResponse({"error": str(e)}, status=500)
