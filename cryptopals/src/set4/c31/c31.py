import sys
from Crypto import Random
import hashlib
import socket
import re
import hmac
import time



class Hmac:
    # block_size is in bytes. For SHA1 block_size is 64 bytes
    def __init__(self, key, block_size):
        self.key = bytearray(key)
        self.block_size = block_size
        
        if (len(self.key) > block_size):
            self.key = hashlib.sha1(self.key).digest()
        if (len(self.key) < block_size):
            self.key = self.key + bytearray("\x00" * (block_size - len(self.key)))
        
    
    def get_hex_digest(self, message):
        o_key_pad = bytearray(''.join([chr((b1 ^ b2) & 0xFF) for b1,b2 in zip(bytearray("\x5c" * self.block_size), self.key)]))
        i_key_pad = bytearray(''.join([chr((b1 ^ b2) & 0xFF) for b1,b2 in zip(bytearray("\x36" * self.block_size), self.key)]))
        hmac_digest = hashlib.sha1(o_key_pad + hashlib.sha1(i_key_pad + bytearray(message)).digest()).hexdigest()
        expected_digest = hmac.new(self.key, message, hashlib.sha1).hexdigest()
        if expected_digest != hmac_digest:
            raise()
        return hmac_digest

    
class WebServer:
    def __init__(self, host, port, backlog = 1):
        self.host = host
        self.port = port

        # initialize a TCP socket 
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((self.host, self.port))
        self.sock.listen(backlog)

        # generate a key that is used to sign all messages
        key = "bar"
        self.mac_helper = Hmac(key, 64)

        print "serving HTTP on port %s" % self.port
        while True:
            # wait for incoming client connections
            client_conn, client_addr = self.sock.accept()
            request = client_conn.recv(1024)
            print request
            
            # validate the request and obtain response
            response = self.get_response(request)
            print "sending response to client: " + response
            print "\n\n"
            client_conn.sendall(response)
            client_conn.close()
    
    def insecure_compare(self, exp_signature, real_signature):
        if len(exp_signature) != len(real_signature):
            return False
        for b1, b2 in zip(exp_signature, real_signature):
            # artificial timing delay here
            time.sleep(0.05)
            if b1 != b2:
                return False
        return True
            
    # compare the expected and actual signatures from the request and generate a response
    def get_response(self, request):
        matches = re.findall("file=[a-zA-Z0-9 ]*&signature=[a-zA-Z0-9]{40}$", request)
        if (len(matches) != 1):
            return """HTTP/1.1 400 Bad Request"""
        kvp = matches[0].split('&')
        filename = kvp[0][5:]
        signature = kvp[1][10:]
        print "file: " + filename
        expected_signature = self.mac_helper.get_hex_digest(filename)
        print expected_signature
        if self.insecure_compare(expected_signature, signature) == False:
            return """HTTP/1.1 401 Unauthorized request"""
        return """HTTP/1.1 200 OK\n Hello World"""



if __name__ == "__main__":
    argc = len(sys.argv)
    if argc != 3:
        print "usage:%s host port" % sys.argv[0]
        exit(0)
    host = sys.argv[1]
    port = int(sys.argv[2])
    server = WebServer(host, port)
    