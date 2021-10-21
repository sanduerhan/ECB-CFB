import socket
import os
import secrets
from _thread import *
# from Crypto.Cipher import AES
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ServerSocket = socket.socket()
host = '127.0.0.1'
port = 1236
ThreadCount = 0
kPrim = '4B6250655368566D597133743677397A'
k1 = secrets.token_hex(16)
k2 = secrets.token_hex(16)
iv = b"1234567890123456"

try:
    ServerSocket.bind((host, port))
except socket.error as e:
    print(str(e))

print('Waitiing for a Connection..')
ServerSocket.listen()


def encrypt_ebc(mode_key, key):     #pentru criptarea cheilor k1 k2
    # cipher = AES.new(key.encode(), AES.MODE_EBC)
    cipher = Cipher(algorithms.AES(bytes(key, encoding='utf-8')), modes.ECB())
    encryptor = cipher.encryptor()
    ct = encryptor.update(bytes(mode_key,encoding='utf-8'))+encryptor.finalize()
    return ct


def encrypt_cfb(mode_key, key):
    # cipher = AES.new(key.encode(), AES.MODE_CFB, iv)
    cipher = Cipher(algorithms.AES(bytes(key, encoding='utf-8')), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(bytes(mode_key, encoding='utf-8')) + encryptor.finalize()
    return ct


def threaded_client(connection):
    adrese.append(connection)
    while True:
        if adrese[0] == connection:
            data = connection.recv(2048)
            reply = data.decode('utf-8')
            adrese[1].send(str.encode(reply))
            if reply == 'ECB':
                adrese[0].send(encrypt_ebc(k1, kPrim))
                adrese[1].send(encrypt_ebc(k1, kPrim))
                data2 = connection.recv(2048)
                adrese[1].send(data2)
            elif reply == 'CFB':
                adrese[0].send(encrypt_cfb(k2, kPrim))
                adrese[1].send(encrypt_cfb(k2, kPrim))
                data3 = connection.recv(2048)
                adrese[1].send(data3)
           # data = connection.recv(2048)
            #adrese[1].send(str.encode(data.decode('utf-8')))
        elif adrese[1] == connection:
            data = connection.recv(2048)
            start = data.decode('utf-8')
            adrese[0].send(str.encode(start))

        # connection.sendall(str.encode(reply))
    connection.close()


adrese = []
while True:
    Client, address = ServerSocket.accept()
    # adrese[ThreadCount] = address[1]
    print('Connected to: ' + address[0] + ':' + str(address[1]))
    start_new_thread(threaded_client, (Client,))
    ThreadCount += 1
    print('Thread Number: ' + str(ThreadCount))
ServerSocket.close()
