import sys
from random import randint
from crypto_math import CryptoMath
import hashlib

class DSA:
    def __init__(self, p, q, g, x = None, k = None):
        """ initialize parameters"""
        self.p = p
        self.q = q
        self.g = g

        # generate private key x - NOTE : randint is not a secure CSPRNG
        if x == None:
            self.x = randint(1, self.q - 1)
        else:
            self.x = x

        # generate public key g ** x mod p
        self.y = CryptoMath.mod_exp(self.g, self.x, self.p)
        self.k = k


    def get_signature(self, m):
        """ compute and return the DSA signature of a given string message """
        s = 0
        r = 0

        # handle unlikely case where s is equal to zero
        while s == 0:
            # handle unlikely case when r is equal to 0 because of choice of k
            while r == 0:
                # generate a per-message secret k
                k = self.k
                if k == None:
                    k = randint(1, self.q - 1)
                    self.k = k
                
                # calculate r = g ** k (mod p) mod q
                r = CryptoMath.mod_exp(self.g, k, self.p)
                r = CryptoMath.mod_mul(r, 1, self.q)

            # compute H(m) + x*r
            msg_hash = hashlib.sha1(m).hexdigest()
            msg_hash_int = int(msg_hash, 16)
            
            temp = (msg_hash_int + CryptoMath.mod_mul(self.x, r, self.q)) % self.q

            # compute s = k_inv * temp mod q
            k_inv = CryptoMath.mod_inv(k, self.q)
            s = CryptoMath.mod_mul(k_inv, temp, self.q)
        return (r,s)


    def is_signature_valid(self, m, r, s):
        """ compute the expected signature and validate against presented signature """
        if r <= 0 or r >= self.q:
            return False
        if s <= 0 or s >= self.q:
            return False

        # compute w = s_inv mod q
        w = CryptoMath.mod_inv(s, self.q)

        # compute u1 = H(m) * w mod q
        msg_hash = hashlib.sha1(m).hexdigest()
        msg_hash_int = int(msg_hash, 16)
        u1 = CryptoMath.mod_mul(msg_hash_int, w, self.q)

        # compute u2 = r * w mod q
        u2 = CryptoMath.mod_mul(r, w, self.q)

        # compute v = (g ** u1 * y ** u2 mod p) mod q
        t1 = CryptoMath.mod_exp(self.g, u1, self.p)
        t2 = CryptoMath.mod_exp(self.y, u2, self.p)
        v = CryptoMath.mod_mul(t1, t2, self.p)
        v = CryptoMath.mod_mul(v, 1, self.q)
        return v == r

        

if __name__ == "__main__":
    p = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1
    q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
    g = 0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291


    dsa = DSA(p, q, g)
    msg = "hello world!"
    r,s = dsa.get_signature(msg)
    if dsa.is_signature_valid(msg, r, s):
        print "Signature (%d, %d) on message %s is valid!" % (r, s, msg)
    else:
        print "Signature (%d, %d) is invalid!" % (r, s)
