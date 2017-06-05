import sys
from dh import CryptoMath
import hashlib
import socket
from random import randint
from Crypto.Cipher import AES

BASE = 10

class Bob:
    def __init__(self, host, port):
        self.p = None
        self.g = None
        self.A = None
        self.B = None
        self.b = None
        self.secret_key = None
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((host, port))
        self.sock.listen(1)
        self.client_sock, address = self.sock.accept()
        

    def receive_pgA(self):
        data = self.client_sock.recv(4096)
        data_array = data.split(',')
        self.p = int(data_array[0], BASE)
        self.g = int(data_array[1], BASE)
        self.A = int(data_array[2], BASE)
        self.b = randint(2, self.p-2)
        self.B = CryptoMath.mod_exp(self.g, self.b, self.p)
        print self.p
        print self.g
        print self.A

    def send_B(self):
        self.client_sock.send(str(self.B))

    def compute_key(self):
        shared_secret = CryptoMath.mod_exp(self.A, self.b, self.p)
        secret_key = hashlib.sha1(str(shared_secret)).digest()
        self.secret_key = secret_key[0:16]
    
    def decrypt_message(self):
        encrypted_payload = self.client_sock.recv(4096)
        iv_and_cipher = encrypted_payload.split(',')
        iv = iv_and_cipher[0]
        ciphertext = iv_and_cipher[1]
        cipher = AES.new(self.secret_key, AES.MODE_CBC, iv)
        return cipher.decrypt(ciphertext) 

if __name__ == "__main__":
    # python bob.py localhost 8080
    argc = len(sys.argv)
    if argc != 3:
        print "usage: %s host port" % (sys.argv[0])
        exit(-1)
    
    host = sys.argv[1]
    port = int(sys.argv[2], 10)
    bob = Bob(host, port)
    bob.receive_pgA()
    bob.send_B()
    bob.compute_key()
    msg = bob.decrypt_message()
    print "bob received %s" % (msg)

    