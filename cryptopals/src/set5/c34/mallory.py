import sys
import hashlib
from Crypto.Cipher import AES
import socket

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

        

    def receive_pgA_from_alice(self):
        payload = self.alice_sock.recv(4096)
        pga_array = payload.split(',')
        self.p = int(pga_array[0])
        self.g = int(pga_array[1])
        self.A = int(pga_array[2])

    def send_pgp_to_bob(self):
        # injecting the modulus p as Alice's public key and sending it to Bob
        payload = ','.join([str(self.p), str(self.g), str(self.p)])
        self.bob_sock.send(payload)
    
    def receive_B_from_bob(self):
        B = self.bob_sock.recv(4096)
        self.B = int(B)
    
    def send_p_to_alice(self):
        payload = str(self.p)
        self.alice_sock.send(payload)
    
    def determine_secret_key(self):
        # since Mallory has injected the modulus 'p' as Alice's public key to Bob and Bob's public key to Alice
        # the shared secret derived by both will be (p**a) % p and (p**b) % p, which is essentially 0
        shared_secret = 0
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

    mallory = Mallory(mallory_host, mallory_port, bob_host, bob_port)
    mallory.receive_pgA_from_alice()
    mallory.send_pgp_to_bob()
    mallory.receive_B_from_bob()
    mallory.send_p_to_alice()
    mallory.determine_secret_key()
    iv, ct = mallory.receive_encrypted_message()
    mallory.send_encrypted_message_to_bob(iv, ct)

    

