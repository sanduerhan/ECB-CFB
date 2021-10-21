import socket
#from Crypto.Cipher import AES
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
padder = padding.PKCS7(256).padder()
ClientSocket = socket.socket()
host = '127.0.0.1'
port = 1236
kPrim = '4B6250655368566D597133743677397A'
iv = b"1234567890123456"

def decrypt_ecb(mode_key,key):
    #cipher = AES.new(kPrim.encode(), AES.MODE_EBC)
    cipher = Cipher(algorithms.AES(bytes(key, encoding='utf-8')), modes.ECB())
    decryptor = cipher.decryptor()
    toByte = bytes(mode_key, encoding='utf-8').ljust(128)
    ct = decryptor.update(toByte) + decryptor.finalize()
    return ct

def decrypt_cfb(mode_key,key):
    #cipher = AES.new(kPrim.encode(), AES.MODE_CFB, iv)
    cipher = Cipher(algorithms.AES(bytes(key, encoding='utf-8')), modes.CFB(iv))
    decryptor = cipher.decryptor()
    toByte = bytes(mode_key, encoding='utf-8').ljust(128)
    ct = decryptor.update(toByte) + decryptor.finalize()
    return ct

def mod_ecb(plaintext, k):
    cipher = Cipher(algorithms.AES(k[:16]), modes.ECB())
    encryptor = cipher.encryptor()
    cipherblock = ''
    cipherblock = bytes(cipherblock,'utf-8')
    blocks = [plaintext[i:i+16] for i in range(0,len(plaintext),16)]            #impartim pe blocuri de 16bytes plaintextul
    if len(blocks[-1]) < 16:
        blocks[-1] = blocks[-1].ljust(16)       #padding pentru ultimul bloc
    for i in blocks:
        cipherblock += encryptor.update(i.encode('utf-8'))      #pentru fiecare bloc criptam cu ajutorul cheii primite
        #ciphertext +=cipherblock
    return cipherblock

def byte_xor(ba1, ba2):     #functie de xorare
    return bytes([_a ^ _b for _a, _b in zip(ba1,ba2)])

def mod_cfb(plaintext, k):
    cipher = Cipher(algorithms.AES(k[:16]), modes.ECB())
    encryptor = cipher.encryptor()
    temp = iv
    ciphertext = ''
    ciphertext = bytes(ciphertext, 'utf-8')
    blocks = [plaintext[i:i + 16] for i in range(0, len(plaintext), 16)]        #impartim in blocuri plaintextul
    if len(blocks[-1]) < 16:
        blocks[-1] = blocks[-1].ljust(16)       #padding
    for i in blocks:
        result = encryptor.update(temp)         #criptam initial vectorul de initializare dupa care rezultatul xorului
        xor = byte_xor(i.encode('utf-8'),result)    #xoram blocul cu rezultatul criptarii
        ciphertext += xor
        temp = xor      #next pentru criptare
    return ciphertext

try:
    ClientSocket.connect((host, port))
except socket.error as e:
    print(str(e))

while True:
    mod = input("Introduceti modul de operare: ")
    ClientSocket.send(str.encode(mod))
    cheie = ClientSocket.recv(2048)
    cheie_enc = cheie.decode('latin-1')
    #print(cheie_enc)
    f = open("demofile.txt", "r")
    plaintext = f.read()
    print(plaintext)
    Response = ClientSocket.recv(2048)
    start = Response.decode('latin-1')
    print(start)
    if start == '1':
        if mod == 'ECB':
            key = decrypt_ecb(cheie_enc, kPrim)
            ciphertext = mod_ecb(plaintext, key)
            ClientSocket.send(ciphertext)
        elif mod == 'CFB':
            key = decrypt_cfb(cheie_enc, kPrim)
            ciphertext = mod_cfb(plaintext, key)
            #print(ciphertext)
            ClientSocket.send(ciphertext)



ClientSocket.close()