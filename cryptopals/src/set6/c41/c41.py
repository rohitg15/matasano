import sys
from crypto_math import RSAHelper, CryptoMath
import hashlib
from Crypto.Util.number import getPrime
from random import randint


class MessageServer:
    def __init__(self, msg_hashes = None):
        # generate primes and initialize RSA helper
        # divisible by 3
        p = 1
        q = 1
        e = 3
        while((p % e) == 1):
            p = getPrime(1024)
        while((q % e) == 1):
            q = getPrime(1024)
        print "prime 1 : %d" % (p)
        print "prime 2 : %d" % (q)
        
        self.rsa = RSAHelper(p, q, e)
        self.msg_hashes = {}
        if msg_hashes is not None:
            for mhash in msg_hashes:
                self.msg_hashes[mhash] = True
    

    def get_server_public_key(self):
        return (self.rsa.e, self.rsa.n)

    def get_encrypted_message(self, msg):
        """ accepts a plaintext message, converts to hex and returns the encrypted ciphertext using RSA"""
        hex_msg = msg.encode('hex')
        m = int(hex_msg, 16)
        print "m : %d" % (m)
        c = self.rsa.encrypt(m)
        return c

    def get_decrypted_message(self, c):
        """ accepts an encrypted message, validates to make sure that it was not submitted already and returns
            the decrypted output."""
        
        m = self.rsa.decrypt(c)
        msg = str(hex(m))[2:-1]

        msg_hash = hashlib.sha256(msg).hexdigest()
        
        # validate against known hashes for potential message replays
        for known_hash in self.msg_hashes.keys():
            if msg_hash == known_hash:
                raise ValueError("Error: replay attack detected!")
        
        return m



if __name__ == "__main__":
    # initialize server
    message = """{
  time: 1356304276,
  social: '555-55-5555',
}
"""
    server = MessageServer()
    
    # this is just for local debugging (and to get the original ciphertext)
    c = server.get_encrypted_message(message)
    valid_m = server.get_decrypted_message(c)
    valid_message = str(hex(valid_m))[2:-1].decode('hex')
    assert(valid_message == message)
    msg_hash = hashlib.sha256(message.encode('hex')).hexdigest()
    e, n = server.get_server_public_key()
    print "server e, n : (%d, %d)" % (e, n)

    # exploit unpadded RSA
    # generate random integer modulo n
    r = randint(2, n-1) % n

    # compute s = (r ** e) % n
    s = CryptoMath.mod_exp(r, e, n)

    # multiply ciphertext c and s under modulo n
    cp = CryptoMath.mod_mul(c, s, n)

    decrypted_cp = server.get_decrypted_message(cp)

    # compute modular inverse of r under modulo n
    r_inv = CryptoMath.mod_inv(r, n)

    # recover original plaintext by multiplying decrypted_cp with r_inv under modulo n
    m = CryptoMath.mod_mul(r_inv, decrypted_cp, n)

    print "recovered: %d" % (m)
    decrypted_msg = str(hex(m))[2:-1].decode('hex')

    print decrypted_msg

