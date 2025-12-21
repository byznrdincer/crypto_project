from django.urls import path
from . import views
from .views import receive_message

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
    path("receive/", views.receive_message),
    path("receive-des-lib/", views.receive_des_lib),
    path("receive-aes-manual/", views.receive_aes_manual),
    path("receive-des-manual/", views.receive_des_manual),
]