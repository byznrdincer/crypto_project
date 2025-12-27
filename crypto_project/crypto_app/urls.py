from django.urls import path
from . import views

urlpatterns = [
    # 🏠 Ana sayfa
    path("", views.home, name="home"),

    # 🔐 ŞİFRELEME (API)
    path("encrypt/", views.encrypt),
    path("decrypt-api/", views.decrypt),  # 👈 API AYRI

    # 🔓 DEŞİFRE SAYFASI (HTML)
    path("decrypt/", views.decrypt_page, name="decrypt_page"),

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

    path("receive/", views.receive_message),
    path("receive-des-lib/", views.receive_des_lib),

    path("receive-aes-manual/", views.receive_aes_manual),
    path("receive-des-manual/", views.receive_des_manual),
    path("receive-aes-manual-decrypt/", views.receive_aes_manual_decrypt),
    path("receive-des-manual-decrypt/", views.receive_des_manual_decrypt),

    path("encrypt-file/", views.encrypt_file_aes_rsa),
    path("decrypt-file/", views.decrypt_file_aes_rsa),

    path("encrypt-file-des/", views.encrypt_file_des_rsa),
    path("decrypt-file-des/", views.decrypt_file_des_rsa),

    path("file/caesar/encrypt/", views.caesar_encrypt_file),
    path("file/caesar/decrypt/", views.caesar_decrypt_file),

    path("file/vigenere/encrypt/", views.vigenere_encrypt_file),
    path("file/vigenere/decrypt/", views.vigenere_decrypt_file),

    path("file/affine/encrypt/", views.affine_encrypt_file),
    path("file/affine/decrypt/", views.affine_decrypt_file),

    path("file/substitution/encrypt/", views.substitution_encrypt_file),
    path("file/substitution/decrypt/", views.substitution_decrypt_file),

    path("file/railfence/encrypt/", views.railfence_encrypt_file),
    path("file/railfence/decrypt/", views.railfence_decrypt_file),
    path("decrypt-aes-lib/", views.decrypt_aes_rsa_text),
    path("decrypt-des-rsa-text/", views.decrypt_des_rsa_text),


]
