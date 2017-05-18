import sys
import socket
from random import randint
from dh import CryptoMath
from Crypto.Cipher import AES
import struct
import hashlib

class Bob:
    BACKLOG_COUNT = 5
    MAX_SIZE = 1024 * 10
    def __init__(self, host = "127.0.0.1", port=8080):
        """initialize server parameters"""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((host, port))
        self.sock.listen(Bob.BACKLOG_COUNT)
        print "[*] server initialized. Bound to %s, port %s!" % (host, str(port))
        
    def __get_shared_key__(self, client_pub_key):
        """return the shared secret key derived from the dh keys"""
        shared_key = CryptoMath.mod_exp(client_pub_key, self.b, self.p)
        return hashlib.sha1(str(shared_key)).digest()
        
    def __exchange_params__(self, client_sock, address):
        """negotiate DH keys and establish a shared secret key with the client"""
        # receive p, g, A from client
        header = client_sock.recv(2048)
        dh_params = header.split(',')
        self.p = int(dh_params[0], 10)
        self.g = int(dh_params[1], 10)
        client_pub_key = int(dh_params[2], 10)

        # generate server's dh public and private keys
        self.b = randint(1, self.p-1)
        self.B = CryptoMath.mod_exp(self.g, self.b, self.p)
        self.shared_key = self.__get_shared_key__(client_pub_key)
        print "[*] modulus=%d" % (self.p)
        print "[*] generator=%d" % (self.g)
        print "[*] client's public key %d" % (client_pub_key) 
        print "[*] shared_key=%s" % (self.shared_key)

        # send server's public key to client
        print "[*] generated server public key %s" % (str(self.B))
        client_sock.send(str(self.B))
        print "[*] established dh shared key with client %s " % (address)

    def __decrypt_messages__(self, client_sock, address):
        """use the shared key to decrypt client messages"""
        # receive payload length
        header = client_sock.recv(8)
        payload_length = struct.unpack("<Q",header)[0]
        print "[*] received header : %d from client" % (payload_length)

        if payload_length > Bob.MAX_SIZE:
            raise ValueError("received payload with length " + str(payload_length) + " from client " + address)
        
        # get payload from client and decrypt
        client_sock.send("OK")
        payload = client_sock.recv(payload_length)
        payload = payload.split(',')
        iv = payload[0]
        ciphertext = payload[1]
        print "[*] received iv=%s ciphertext=%s from client %s" %(iv, ciphertext, address)

        aes = AES.new(self.shared_key[0:16], AES.MODE_CBC, iv)
        return aes.decrypt(ciphertext)
        

    def listen(self):
        """wait for incoming connections"""
        print "[*] listening for incoming connections..."
        #try:
        while 1:
            client_sock, address = self.sock.accept()
            address = str(address)
            #try:
            self.__exchange_params__(client_sock, address)
            client_message = self.__decrypt_messages__(client_sock, address)
            print "[*] client %s sent message : %s" %(address, client_message)
            #except:
            #    print sys.exc_info()
            #    client_sock.close()
            #    break
            client_sock.close()
        #except:
        #    print sys.exc_info()
        #    self.sock.close()


if __name__ == "__main__":
    argc = len(sys.argv)
    if argc != 2:
        print "usage: %s port" % (sys.argv[0])
        exit(-1)
    port = int(sys.argv[1])
    bob = Bob("localhost", port)
    bob.listen()