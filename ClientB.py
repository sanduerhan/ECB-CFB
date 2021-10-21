import socket
#from Crypto.Cipher import AES
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
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

def dec_ecb(ciphertext, mod_key):
    #cipher = AES.new(mod_key.encode(), AES.MODE_ECB)
    cipher = Cipher(algorithms.AES(mod_key[:16]), modes.ECB())
    decryptor = cipher.decryptor()
    cipherblock = ''
    cipherblock = bytes(cipherblock, 'utf-8')
    blocks = [ciphertext[i:i + 16] for i in range(0, len(ciphertext), 16)]
    for i in blocks:
        cipherblock += decryptor.update(i)
    return cipherblock.decode('latin-1').strip()

def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1,ba2)])

def dec_cfb(ciphertext, mod_key):
    cipher = Cipher(algorithms.AES(mod_key[:16]), modes.ECB())
    encryptor = cipher.encryptor()
    temp = iv
    plaintext = ''
    plaintext = bytes(plaintext, 'utf-8')
    blocks = [ciphertext[i:i + 16] for i in range(0, len(ciphertext), 16)]
    for i in blocks:
        result = encryptor.update(temp)
        xor = byte_xor(result, i)
        plaintext += xor
        temp = i
    return plaintext.decode('utf-8').strip()

try:
    ClientSocket.connect((host, port))
except socket.error as e:
    print(str(e))

while True:
    Response = ClientSocket.recv(1024)
    mod_operare = Response.decode('utf-8')
    print(mod_operare)
    cheie = ClientSocket.recv(2048)
    cheie_enc = cheie.decode('latin-1')
    if 'ECB' in mod_operare:
        start = input("Putem incepe comunicarea: ")
        ClientSocket.send(str.encode(start))
        text = ClientSocket.recv(2048)
        #ciphertext = text.decode('utf-8')
        #print(ciphertext)
        key = decrypt_ecb(cheie_enc, kPrim)
        plaintext = dec_ecb(text,key)
        print(plaintext)
    elif 'CFB' in mod_operare:
        start = input("Putem incepe comunicarea: ")
        ClientSocket.send(str.encode(start))
        key = decrypt_cfb(cheie_enc, kPrim)
        text = ClientSocket.recv(2048)
        plaintext = dec_cfb(text, key)
        print(plaintext)


ClientSocket.close()