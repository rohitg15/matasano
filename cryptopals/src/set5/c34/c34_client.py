import sys
import socket
import base64
from random import randint
from dh import CryptoMath
from Crypto.Cipher import AES
import hashlib
import struct
from Crypto import Random

class Alice:
    def __init__(self, host, port):
        """initialize a client socket to start the communication"""
        self.block_size = 16
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.host = host
        self.port = port
        self.shared_key = None
        self.sock.connect((self.host, self.port))

    def __del__(self):
        """tear down connection"""
        self.sock.close()

        
    def exchange_params(self):
        # send p, g, a as csv's. send the total length of the payload first
        payload = ','.join([str(self.p), str(self.g), str(self.A)])
        
        # send initial payload to server
        print "[*] modulus=%d" % (self.p)
        print "[*] generator=%d" % (self.g)
        print "[*] client's public key=%d" % (self.A)
        self.sock.send(payload)
        return self.sock.recv(2048)

    def get_shared_key(self, server_pub_key):
        # compute shared key at client's end
        shared_key = CryptoMath.mod_exp(server_pub_key, self.a, self.p)
        return hashlib.sha1(str(shared_key)).digest()
        
    def get_encrypted_message(self, key, msg):
        iv = Random.get_random_bytes(self.block_size)
        aes = AES.new(key, AES.MODE_CBC, iv)
        return (iv, aes.encrypt(msg))

    def send_encrypted_message(self, msg="A"*16):
        iv, ciphertext = self.get_encrypted_message(self.shared_key[0:16], msg)
        payload = ','.join([iv, ciphertext])
        header = struct.pack('<Q', len(payload))
        # send payload length first
        self.sock.send(header)
        ack = self.sock.recv(2)
        if ack == "OK":
            self.sock.sendall(payload)
            print "[*] sent %d bytes. payload = %s" % (len(payload), payload)
        else:
            print "[*] server rejected payload with size %d" % (len(payload))
        
        
    def setup_shared_keys(self, p, g):
        """start key exchange protocol using DH. p, g are integers in base 10"""
        print "[*] generating dh keys for client..."
        self.p = p
        self.g = g
        self.a = randint(1, self.p-1)
        self.A = CryptoMath.mod_exp(self.g, self.a, self.p)

        server_pub_key = int(self.exchange_params(), 10)
        print "[*] received server's public key %d" % (server_pub_key)
        self.shared_key = self.get_shared_key(server_pub_key)
        print "[*] shared key=%s" % (self.shared_key)
        return self.shared_key
        


        




if __name__ == "__main__":
    argc = len(sys.argv)
    if argc != 5:
        print "[*] usage: %s modulus(hex) generator host port" % (sys.argv[0])
        exit(-1)
    p = int(sys.argv[1], 16)
    g = int(sys.argv[2], 10)
    host = sys.argv[3]
    port = int(sys.argv[4])
    
    alice = Alice(host, port)
    alice.setup_shared_keys(p, g)
    alice.send_encrypted_message()