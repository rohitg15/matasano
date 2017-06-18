import sys
import socket
from dh import CryptoMath
from random import randint
import hashlib
import hmac
import base64


class Server:
    N = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
    g = 2
    k = 3


    def __init__(self, host, port, password = "HelloWorld!"):
        """ initialize server socket, wait for connections from client """
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((host, port))
        self.sock.listen(5)

        self.P = password
        self.v, self.salt = self.__generate_secrets__()
        print "INFO [*] : server listening on %s:%d" % (host, port)
        self.csock, addr = self.sock.accept()
        print "INFO [*] : client %s has connected" % (str(addr))
        print "DEBUG [*] : server's password %s" % (self.P)
        
    def __generate_secrets__(self):
        """ generate salt, compute hash of salt|password and generate dH public key from the hash"""
        salt = randint(1, Server.N - 1)
        xH = hashlib.sha256(str(salt) + self.P).hexdigest()
        x = int(xH, 16)
        print "generated xH as %s and x as %d" % (xH, x)
        v = CryptoMath.mod_exp(Server.g, x, Server.N)
        return (v, salt)

    def receive_dh_key(self):
        """ retrieve client's email and public key"""
        email_pubkey = self.csock.recv(1024)
        email = email_pubkey.split('&')[0][len("email="):]
        self.A = int(email_pubkey.split('&')[1][len("pubkey="):])
        self.I = email
        print "INFO [*] : received client's email %s and public key %d" % (self.I, self.A)

    def send_dh_key(self):
        """ send salt and dH public key to client"""
        self.b = randint(1, Server.N - 1)
        self.B = Server.k * self.v +  CryptoMath.mod_exp(Server.g, self.b, Server.N)
        payload = "salt=" + str(self.salt) + "&" + "pubkey=" + str(self.B)
        self.csock.send(payload)
        print "INFO [*] : send salt %d and server's public key %d to client" % (self.salt, self.B)

    def compute_shared_pubkey(self):
        """ compute the shared public number as the sha256 hash of A|B"""
        self.uH = hashlib.sha256(str(self.A) + str(self.B)).hexdigest()
        self.u = int(self.uH, 16)
        print "INFO [*] : computed shared public key as %d" % (self.u)

    def compute_secret_key(self):
        """ generate the shared secret key from the client's public key, server's private exponent and known password """
        S = (self.A * CryptoMath.mod_exp(self.v, self.u, Server.N))
        S = CryptoMath.mod_exp(S, self.b, Server.N)
        print "DEBUG [*] : computed shared secret number S : %d" % (S)
        self.K = hashlib.sha256(str(S)).hexdigest()
        print "DEBUG [*] generated shared secret key as %s" % (self.K)

    def validate_message(self):
        """ receive base64 encoded message and MAC from client, validate the MAC and send ACK"""
        payload = self.csock.recv(4096)
        payload = payload.split('&')
        # message is prefixed with 'message='
        encoded_message = payload[0][len("message="):]
        message = base64.b64decode(encoded_message)

        # signature is prefixed with 'signature='
        actual_signature = payload[1][len("signature="):]
        
        # compute expected signature
        expected_signature = hmac.new(self.K, message, digestmod=hashlib.sha256).hexdigest()

        # this is probably an insecure signature comparison as it might lead to a timing leak
        response = "OK"
        if expected_signature != actual_signature:
            response = "AUTH Failure"
            print "INFO [*] : client Auth Failure"
        else:
            print "INFO [*] : client Auth Success"
        self.csock.send(response)



    def __del__(self):
        print "INFO [*] : closing connection to client"
        self.csock.close()
        print "INFO [*] : terminating server"
        self.sock.close()

    

if __name__ == "__main__":
    argc = len(sys.argv)
    if argc != 2:
        print "usage : %s port" % (sys.argv[0])
        exit(-1)
    port = int(sys.argv[1])
    s = Server("127.0.0.1", port)
    s.receive_dh_key()
    s.send_dh_key()
    s.compute_shared_pubkey()
    s.compute_secret_key()
    s.validate_message()
    