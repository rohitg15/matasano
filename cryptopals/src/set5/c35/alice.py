import sys
from dh import CryptoMath
import hashlib
import socket
from random import randint
from Crypto.Cipher import AES
from Crypto import Random

BASE = 16

class Alice:
    def __init__(self, host, port, p, g):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((host, port))
        self.a = None
        self.p = p
        self.g = g
        self.a = None
        self.A = None
        self.B = None
        self.secret_key = None
    
    def send_pg(self):
        self.a = randint(1, self.p - 2)
        payload = ','.join([str(self.p) , str(self.g)])
        self.sock.send(payload)
    
    def receive_ack(self):
        payload = self.sock.recv(4096)
        neg_pg = payload.split(',')
        self.p = int(neg_pg[0])
        self.g = int(neg_pg[1])
        self.A = CryptoMath.mod_exp(self.g, self.a, self.p)
        print "received negotiated group from server" 
    
    def send_A(self):
        self.sock.send(str(self.A))

    def receive_B(self):
        B = self.sock.recv(4096)
        self.B = int(B)

    def compute_key(self):
        shared_secret = CryptoMath.mod_exp(self.B, self.a, self.p)
        secret_key = hashlib.sha1(str(shared_secret)).digest()
        self.secret_key = secret_key[0:16]
    
    def encrypt_and_send_message(self, msg):
        iv = Random.get_random_bytes(16)
        cipher = AES.new(self.secret_key, AES.MODE_CBC, iv)
        encrypted_message = cipher.encrypt(msg)
        payload = ','.join([iv, encrypted_message])
        self.sock.send(payload)

    def __del__(self):
        self.sock.close()



if __name__ == "__main__":
    # python alice.py localhost 8888 ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff 2
    argc = len(sys.argv)
    if argc != 5:
        print "usage: %s host port p g" % (sys.argv[0])
        exit(-1)
    
    server_host = sys.argv[1]
    server_port = int(sys.argv[2])
    p = int(sys.argv[3], BASE)
    g = int(sys.argv[4], BASE)
    alice = Alice(server_host, server_port, p, g)
    alice.send_pg()
    alice.receive_ack()
    alice.send_A()
    alice.receive_B()
    alice.compute_key()
    msg = "A" * 16
    print "alice sending %s" % (msg)
    alice.encrypt_and_send_message(msg)