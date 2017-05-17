import sys
import dh
import socket
import base64

class Bob:
    def __init__(self, host = "127.0.0.1", port=8080):
        """initialize server parameters"""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((host, port))
        self.sock.listen()
        print "server initialized. Bound to %s, port %s!\nwaiting for incoming connections..." % (host, str(port))
        
    
    def setup_shared_key(self):
        """wait for incoming connections"""
        print "listening for incoming connections..."
