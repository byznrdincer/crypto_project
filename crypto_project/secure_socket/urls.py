from django.urls import path
from . import views

urlpatterns = [
    path("aes/encrypt/", views.aes_encrypt_library),
    path("aes/decrypt/", views.aes_decrypt_library),
    path("des/encrypt/", views.des_encrypt_library),
    path("des/decrypt/", views.des_decrypt_library),
    path("rsa/generate/", views.rsa_generate_keys),
    path("rsa/encrypt/", views.rsa_encrypt_view),
    path("rsa/decrypt/", views.rsa_decrypt_view),
]
