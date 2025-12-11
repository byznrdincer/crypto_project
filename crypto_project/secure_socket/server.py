import socket
from crypto.aes_lib import aes_decrypt

HOST = "0.0.0.0"
PORT = 9000

server = socket.socket()
server.bind((HOST, PORT))
server.listen(1)
print("Server listening...")

conn, addr = server.accept()
print("Connected:", addr)

cipher = conn.recv(4096).decode()
print("Encrypted:", cipher)

plain = aes_decrypt(cipher, "mykey1234567890")
print("Decrypted:", plain)

conn.close()
server.close()
