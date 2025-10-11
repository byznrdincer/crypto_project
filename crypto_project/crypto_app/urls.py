from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('encrypt/', views.encrypt, name='encrypt'),
    path('decrypt/', views.decrypt, name='decrypt'),
    path('vigenere/encrypt/', views.vigenere_encrypt, name='vigenere_encrypt'),
    path('vigenere/decrypt/', views.vigenere_decrypt, name='vigenere_decrypt'),

]
