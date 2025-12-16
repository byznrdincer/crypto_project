from django.urls import path
from . import views

urlpatterns = [
    # 🏠 Ana sayfa
    path("", views.home, name="home"),

    # =======================
    # KLASİK CIPHERLAR
    # =======================
    path("encrypt/", views.encrypt),
    path("decrypt/", views.decrypt),

    path("vigenere/encrypt/", views.vigenere_encrypt),
    path("vigenere/decrypt/", views.vigenere_decrypt),

    path("affine/encrypt/", views.affine_encrypt),
    path("affine/decrypt/", views.affine_decrypt),

    path("substitution/encrypt/", views.substitution_encrypt),
    path("substitution/decrypt/", views.substitution_decrypt),

    path("railfence/encrypt/", views.railfence_encrypt),
    path("railfence/decrypt/", views.railfence_decrypt),

    path("columnar/encrypt/", views.columnar_encrypt),
    path("columnar/decrypt/", views.columnar_decrypt),

    path("hill/encrypt/", views.hill_encrypt),
    path("hill/decrypt/", views.hill_decrypt),

    path("vernam/encrypt/", views.vernam_encrypt),
    path("vernam/decrypt/", views.vernam_decrypt),

    # =======================
    # AES / DES (LIBRARY)
    # =======================
    path("aes/encrypt/", views.aes_encrypt_library),
    path("aes/decrypt/", views.aes_decrypt_library),

    path("des/encrypt/", views.des_encrypt_library),
    path("des/decrypt/", views.des_decrypt_library),

    # =======================
    # RSA
    # =======================
    path("rsa/generate/", views.rsa_generate_keys),
    path("rsa/encrypt/", views.rsa_encrypt_view),
    path("rsa/decrypt/", views.rsa_decrypt_view),
]
