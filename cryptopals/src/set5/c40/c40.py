import sys
from crypto_math import CryptoMath
from Crypto.Util.number import getPrime


class RSAHelper:
    def __init__(self, p = 71, q = 77, e = 3):
        print "RSA Helper"
        self.n = p * q
        self.et = (p - 1) * (q - 1)
        self.e = e
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
    
    m = 42

    # generate 3 public, private keys
    bits = 1024
    e = [3, 3, 3]
    c = []
    n = []
    k = len(e)
    table = {}
    for i in range(k):
        p = 1
        q = 1
        while 1:
            # this while loop ensures that the totient would be co-prime with e[i]
            while ((p % e[i]) == 1):
                p = getPrime(bits)

            while ((q % e[i]) == 1):
                q = getPrime(bits)
            
            # compute the modulus from the 2 primes
            modulus = p * q
            if table.has_key(modulus) == False:
                table[modulus] = True
                n.append(modulus)
                break

        # encrypt the message m using RSA with public/private keys generated from the above primes
        print "---------- round %d ----------" % (i)
        rsa = RSAHelper(p, q, e[i])
        ct = rsa.encrypt(m)
        assert(m == rsa.decrypt(ct))

        # once we assert that enc/dec succeeded, we know that this is a valid RSA ciphertext
        # the above test is just done as a sanity check to help me debug the code easily in case of errors
        c.append(ct)
        print "\n"
    
    # use chinese remainder theorem to solve for the plaintext message
    p = CryptoMath.solve_crt(c, n)

    # get the cube root
    p = int(round((p ** (1./3))))
    print "decrypted plaintext : %d" % (p)
    assert(p == m)

