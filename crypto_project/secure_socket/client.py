import socket
from crypto.aes_lib import aes_encrypt

HOST = "127.0.0.1"
PORT = 9000

message = input("Mesaj: ")
key = "mykey1234567890"

cipher = aes_encrypt(message, key)

sock = socket.socket()
sock.connect((HOST, PORT))
sock.send(cipher.encode())
sock.close()

print("Gönderildi!")
