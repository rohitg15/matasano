import sys
import hashlib
from Crypto.Cipher import AES
import socket
from random import randint

class Mallory:
    def __init__(self, mallory_host, mallory_port, bob_host, bob_port):
        self.p = None
        self.g = None
        self.A = None
        self.B = None
        self.secret_key = None

        # perform TCP handshake with Bob
        self.bob_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.bob_sock.connect((bob_host, bob_port))

        # listen for incoming connections from Alice
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((mallory_host, mallory_port))
        self.sock.listen(1)
        self.alice_sock, address = self.sock.accept()

        

    def receive_pg_from_alice(self):
        payload = self.alice_sock.recv(4096)
        pg_array = payload.split(',')
        self.p = int(pg_array[0])
        self.g = int(pg_array[1])
    
    def send_crafted_pg_to_bob(self, g):
        # modify the group and send it to bob
        self.g = g
        payload = ','.join([str(self.p), str(self.g)])
        self.bob_sock.send(payload)
    
    def receive_negotiated_group_from_bob(self):
        payload = self.bob_sock.recv(4096)
        pg_array = payload.split(',')
        self.p = int(pg_array[0])
        self.g = int(pg_array[1])
    
    def send_negotiated_group_to_alice(self):
        payload = ','.join([str(self.p), str(self.g)])
        self.alice_sock.send(payload)

    def receive_A_from_alice(self):
        A = self.alice_sock.recv(4096)
        self.A = int(A)
        print "got %d as alice's public key" % (self.A)
    
    def send_A_to_bob(self):
        self.bob_sock.send(str(self.A))
        
    def receive_B_from_bob(self):
        B = self.bob_sock.recv(4096)
        self.B = int(B)
        print "got %d as bob's public key" % (self.B)
    
    def send_B_to_alice(self):
        payload = str(self.B)
        self.alice_sock.send(payload)
    
    def determine_secret_key(self):
        # since Mallory has injected the group generator (1, p, p-1), the shared key computed by alice and bob
        # can be deterministically computed by mallory
        if self.g == 1 or self.g == self.p - 1:
            shared_secret = 1
        elif self.g == self.p:
            shared_secret = 0
        else:
            raise("modulus set to invalid value %d" % (self.p) )
        self.secret_key = hashlib.sha1(str(shared_secret)).digest()[0:16]

    def receive_encrypted_message(self):
        # receive payload from alice as iv,ciphertext
        encrypted_payload = self.alice_sock.recv(8000)
        iv_and_ct = encrypted_payload.split(',')
        iv = iv_and_ct[0]
        ciphertext = iv_and_ct[1]
        
        cipher = AES.new(self.secret_key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext)
        print "mallory received %s from Alice" % (plaintext)
        return (iv, ciphertext)
    
    def send_encrypted_message_to_bob(self, iv, ciphertext):
        # relay iv and encrypted message to bob
        payload = ','.join([iv, ciphertext])
        self.bob_sock.send(payload)

    def __del__(self):
        self.alice_sock.close()
        self.bob_sock.close()

class Attack:
    """wrapper class to perform man-in-the-middle attack and tamper 
        with the group generator for unauthenticated diffie hellman"""
    def __init__(self, mallory_host, mallory_port, bob_host, bob_port):
        self.mallory = Mallory(mallory_host, mallory_port, bob_host, bob_port)
    
    def start_mitm(self, g):
        self.mallory.receive_pg_from_alice()
        self.mallory.send_crafted_pg_to_bob(g)
        self.mallory.receive_negotiated_group_from_bob()
        self.mallory.send_negotiated_group_to_alice()
        self.mallory.receive_A_from_alice()
        self.mallory.send_A_to_bob()
        self.mallory.receive_B_from_bob()
        self.mallory.send_B_to_alice()
        self.mallory.determine_secret_key()
        iv, ct = self.mallory.receive_encrypted_message()
        self.mallory.send_encrypted_message_to_bob(iv, ct)




if __name__ == "__main__":
    # python mallory.py localhost 8888 localhost 8080
    argc = len(sys.argv)
    if argc != 5:
        print "usage: %s mallory_host mallory_port bob_host bob_port" % (sys.argv[0])
        exit(-1)
    mallory_host = sys.argv[1]
    mallory_port = int(sys.argv[2])
    bob_host = sys.argv[3]
    bob_port = int(sys.argv[4])

    mitm = Attack(mallory_host, mallory_port, bob_host, bob_port)
    
    p = int("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16) 
    generators = [1, p, p-1]
    r = randint(0, 2)
    mitm.start_mitm(generators[r]) 
    
    

