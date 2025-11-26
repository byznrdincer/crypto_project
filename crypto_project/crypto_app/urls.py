from django.urls import path
from . import views
from .views import (
    vernam_encrypt, vernam_decrypt,
    rsa_generate, rsa_encrypt_view, rsa_decrypt_view,
    aes_encrypt, aes_decrypt
)

urlpatterns = [
    # 🏠 Ana sayfa
    path("", views.home, name="home"),

    # ============================================================
    # 🔐 Caesar Cipher
    # ============================================================
    path("encrypt/", views.encrypt, name="encrypt"),
    path("decrypt/", views.decrypt, name="decrypt"),

    # ============================================================
    # 🔐 Vigenère Cipher
    # ============================================================
    path("vigenere/encrypt/", views.vigenere_encrypt, name="vigenere_encrypt"),
    path("vigenere/decrypt/", views.vigenere_decrypt, name="vigenere_decrypt"),

    # ============================================================
    # 🔐 Affine Cipher
    # ============================================================
    path("affine/encrypt/", views.affine_encrypt, name="affine_encrypt"),
    path("affine/decrypt/", views.affine_decrypt, name="affine_decrypt"),

    # ============================================================
    # 🔐 Substitution Cipher
    # ============================================================
    path("substitution/encrypt/", views.substitution_encrypt, name="substitution_encrypt"),
    path("substitution/decrypt/", views.substitution_decrypt, name="substitution_decrypt"),

    # ============================================================
    # 🔐 Rail Fence Cipher
    # ============================================================
    path("railfence/encrypt/", views.railfence_encrypt, name="railfence_encrypt"),
    path("railfence/decrypt/", views.railfence_decrypt, name="railfence_decrypt"),

    # ============================================================
    # 🔐 Columnar Transposition Cipher
    # ============================================================
    path("columnar/encrypt/", views.columnar_encrypt, name="columnar_encrypt"),
    path("columnar/decrypt/", views.columnar_decrypt, name="columnar_decrypt"),

    # ============================================================
    # 🔐 Hill Cipher
    # ============================================================
    path("hill/encrypt/", views.hill_encrypt, name="hill_encrypt"),
    path("hill/decrypt/", views.hill_decrypt, name="hill_decrypt"),

    # ============================================================
    # 🔐 Vernam Cipher
    # ============================================================
    path("vernam/encrypt/", views.vernam_encrypt, name="vernam_encrypt"),
    path("vernam/decrypt/", views.vernam_decrypt, name="vernam_decrypt"),
    # RSA routes
    path("rsa/generate/", rsa_generate),
    path("rsa/encrypt/", rsa_encrypt_view),
    path("rsa/decrypt/", rsa_decrypt_view),

# AES routes
    path("aes/encrypt/", aes_encrypt),
    path("aes/decrypt/", aes_decrypt),

]
