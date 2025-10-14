from django.urls import path
from . import views

urlpatterns = [
    path("", views.home, name="home"),

    # Caesar
    path("encrypt/", views.encrypt, name="encrypt"),
    path("decrypt/", views.decrypt, name="decrypt"),

    # Vigenère
    path("vigenere/encrypt/", views.vigenere_encrypt, name="vigenere_encrypt"),
    path("vigenere/decrypt/", views.vigenere_decrypt, name="vigenere_decrypt"),

    # Affine
    path("affine/encrypt/", views.affine_encrypt, name="affine_encrypt"),
    path("affine/decrypt/", views.affine_decrypt, name="affine_decrypt"),

    # Substitution
    path("substitution/encrypt/", views.substitution_encrypt, name="substitution_encrypt"),
    path("substitution/decrypt/", views.substitution_decrypt, name="substitution_decrypt"),

    # Rail Fence
    path("railfence/encrypt/", views.railfence_encrypt, name="railfence_encrypt"),
    path("railfence/decrypt/", views.railfence_decrypt, name="railfence_decrypt"),
]
