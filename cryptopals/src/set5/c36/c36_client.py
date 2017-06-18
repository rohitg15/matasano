import sys
import socket
from dh import CryptoMath
import hashlib
from random import randint
import hmac
import base64



class Client:
    N = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
    g = 2
    k = 3
    def __init__(self, server_address, server_port, email, password = "HelloWorld!"):
        """ initialize client socket and connect to server"""
        self.I = email
        self.P = password
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((server_address, server_port))
        print "INFO [*] : connected to server at %s:%d " %(server_address, server_port)

    def send_dh_key(self):
        """ generate dh keys and send public key to server """
        self.a = randint(2,Client.N - 1)
        self.A = CryptoMath.mod_exp(Client.g, self.a, Client.N)
        payload = "email=" + self.I + "&" + "pubkey=" + str(self.A)
        self.sock.send(payload)
        print "INFO [*] : sent email %s and public key %d to server" % (self.I, self.A)

    def receive_dh_key(self):
        """ receive server's dH public key and salt"""
        salt_pubkey = self.sock.recv(4096)
        salt_pubkey = salt_pubkey.split('&')
        self.salt = int(salt_pubkey[0][len("salt="):])
        self.B = int(salt_pubkey[1][len("pubkey="):])
        print "INFO [*] : received salt %d and server's public key %d" % (self.salt, self.B)


    def compute_shared_pubkey(self):
        """ compute the shared public number as the sha256 hash of A|B"""
        self.uH = hashlib.sha256(str(self.A) + str(self.B)).hexdigest()
        self.u = int(self.uH, 16)
        print "INFO [*] : computed shared public key as %d" % (self.u)

    def generate_secret_key(self):
        """ compute shared secret key from the server's public key and the client's password """
        xH = hashlib.sha256(str(self.salt) + self.P).hexdigest()
        x = int(xH, 16)
        S = (self.B - Client.k * CryptoMath.mod_exp(Client.g, x, Client.N))
        S = CryptoMath.mod_exp(S, self.a + self.u * x, Client.N)
        self.K = hashlib.sha256(str(S)).hexdigest()
        #print "DEBUG [*] computed shared secret key %s" % (self.K)


    def send_message_with_signature(self, message):
        """ send a base64 encoded message with the corresponding MAC"""
        mac = hmac.new(self.K, message, digestmod=hashlib.sha256).hexdigest()
        encoded_message = base64.b64encode(message)
        payload = "message=" + encoded_message + "&" + "signature=" + mac
        self.sock.send(payload)
        print "INFO [*] : sent message %s with signature %s" % (message, mac)
        response = self.sock.recv(1024)
        if response == "OK":
            print "INFO [*] : Auth Success"
        else:
            print "INFO [*] : Auth Failure"

    def __del__(self):
        print "INFO [*] : closing connection to server"
        self.sock.close()

if __name__ == "__main__":
    argc = len(sys.argv)
    if argc != 4:
        print "usage : %s server_ip_address server_port user_email" % (sys.argv[0])
        exit(-1)
    server_ip = sys.argv[1]
    server_port = int(sys.argv[2])
    user_email = sys.argv[3]
    c = Client(server_ip, server_port, user_email)
    c.send_dh_key()
    c.receive_dh_key()
    c.compute_shared_pubkey()
    c.generate_secret_key()
    c.send_message_with_signature(str(c.salt))