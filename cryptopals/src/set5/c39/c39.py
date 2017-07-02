import sys
from crypto_math import CryptoMath
from Crypto.Util.number import getPrime

class RSAHelper:
    def __init__(self, p = 71, q = 77):
        print "RSA Helper"
        self.n = p * q
        self.et = (p - 1) * (q - 1)
        self.e = 3
        assert(self.et % self.e != 0)
        self.d = CryptoMath.mod_inv(self.e, self.et)
        print "private key %s" % (self.d)
        print "public key : (%d, %d)" % (self.e, self.n)

    def encrypt(self, m):
        assert(m >= 0)
        assert(m <= self.n)
        return CryptoMath.mod_exp(m, self.e, self.n)
    
    def decrypt(self, c):
        assert(c >= 0)
        assert(c <= self.n)
        return CryptoMath.mod_exp(c, self.d, self.n)


if __name__ == "__main__":
    argc = len(sys.argv)
    if argc != 2:
        print "usage: %s message" % (sys.argv[0])
        exit(-1)
    msg = sys.argv[1]
    print "generating large primes..."
    # since 3 is the public exponent we must ensure that the generated primes do not have a totient that is
    # divisible by 3
    p = 1
    q = 1
    while((p % 3) == 1):
        p = getPrime(1024)
    while((q%3) == 1):
        q = getPrime(1024)
    print "prime 1 : %d" % (p)
    print "prime 2 : %d" % (q)
    m = int(msg.encode('hex'), 16)
    print "encoded plaintext : %d" % (m)

    rsa = RSAHelper(p, q)
    c = rsa.encrypt(m)
    print "encrypted ciphertext : %s" % (c)
    md = rsa.decrypt(c)
    print "decrypted plaintext : %s" % (md)
    deciphered_msg = str(hex(md))[2:-1]
    print "decrypted message : %s" % (deciphered_msg.decode('hex'))