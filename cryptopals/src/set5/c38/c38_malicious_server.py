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


    def __init__(self, host, port, password = "somerandompassword"):
        """ initialize server socket, wait for connections from client """
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((host, port))
        self.sock.listen(5)

        self.P = password
        self.v, self.salt = self.__generate_secrets__()
        print "INFO [*] : server listening on %s:%d" % (host, port)
        self.csock, addr = self.sock.accept()
        print "INFO [*] : client %s has connected" % (str(addr))
        
    def __generate_secrets__(self):
        """ generate salt, compute hash of salt|password and generate dH public key from the hash"""
        salt = randint(1, Server.N - 1)
        xH = hashlib.sha256(str(salt) + self.P).hexdigest()
        x = int(xH, 16)
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

        # NOTE: we don't mix the verifier into the server's public key here. 
        # This leads to an offline dictionary attack  because no secret is sent from the client to the server
        # and thus any attacker that impersonates the server, can mount a dictionary attack
        self.B = CryptoMath.mod_exp(Server.g, self.b, Server.N)
        payload = "salt=" + str(self.salt) + "&" + "pubkey=" + str(self.B)
        self.csock.send(payload)
        print "INFO [*] : send salt %d and server's public key %d to client" % (self.salt, self.B)

    def compute_shared_pubkey(self):
        """ compute the shared public number as the sha256 hash of A|B"""
        self.uH = hashlib.sha256(str(self.A) + str(self.B)).hexdigest()
        self.u = int(self.uH, 16)
        print "INFO [*] : computed shared public key as %d" % (self.u)

    def compute_secret_key(self, dict_file):
        """ run a password dictionary attack to guess the password """
        payload = self.csock.recv(4096)
        payload = payload.split('&')

        # ACK the client
        self.csock.send("OK")
        print "INFO [*] : closing connection to client"
        self.csock.close()
        
        # message is prefixed with 'message='
        encoded_message = payload[0][len("message="):]
        message = base64.b64decode(encoded_message)

        # signature is prefixed with 'signature='
        actual_signature = payload[1][len("signature="):]

        with open(dict_file, "r") as file:
            words = file.readlines()
        
        print "INFO [*] : cracking passwords using dictionary %s" % (dict_file)
        for word in words:
            guess = word.strip("\n")
            
            # generate verifier based on guessed password
            xH = hashlib.sha256( str(self.salt) + guess).hexdigest()
            x = int(xH, 16)
            v = CryptoMath.mod_exp(Server.g, x, Server.N)

            # generate shared secret from the verifier computed above
            S = (self.A * CryptoMath.mod_exp(v, self.u, Server.N))
            S = CryptoMath.mod_exp(S, self.b, Server.N)
            Key = hashlib.sha256(str(S)).hexdigest()
            expected_signature = hmac.new(Key, message, digestmod=hashlib.sha256).hexdigest()
            if expected_signature == actual_signature:
                print "Found password: %s, secret key : %s" % (guess, Key)
                return True
        return False

    def __del__(self):
        print "INFO [*] : terminating server"
        self.sock.close()

    

if __name__ == "__main__":
    argc = len(sys.argv)
    if argc != 3:
        print "usage : %s port dict_file" % (sys.argv[0])
        exit(-1)
    port = int(sys.argv[1])
    dict_file = sys.argv[2]

    s = Server("127.0.0.1", port)
    s.receive_dh_key()
    s.send_dh_key()
    s.compute_shared_pubkey()
    s.compute_secret_key(dict_file)
    