import sys
import os
from random import randint


class CryptoMath:
    @staticmethod
    def mod_mul(a, b, n):
        """ returns (a * b) % n without overflowing """
        x = 0
        y = a
        while b > 0:
            if (b & 1) != 0:
                # odd number
                x = (x + y) % n
            y = (y + y) % n
            b = b / 2
        return x % n

    @staticmethod
    def mod_exp(a, b, n):
        """returns (a ** b) % n without overflowing """
        x = 1
        y = a
        while b > 0:
            if (b & 1) != 0:
                # odd number
                x = CryptoMath.mod_mul(x, y, n)
            y = CryptoMath.mod_mul(y, y, n)
            b = b / 2
        return x % n


class DiffieHellman:
    def __init__(self, p, g):
        """Initialize the modulus and generator"""
        self.p = p
        self.g = g
        
    def get_dh_key(self):
        # the random numbers a,b must be in the group modulo p
        self.a = randint(0, self.p)
        self.A = CryptoMath.mod_exp(self.g, self.a, self.p)
    
        self.b = randint(0, self.p)
        self.B = CryptoMath.mod_exp(self.g, self.b, self.p)
        
        # simulate the shared key generation
        self.key_A = CryptoMath.mod_exp(self.B, self.a, self.p)
        self.key_B = CryptoMath.mod_exp(self.A, self.b, self.p)
        assert(self.key_A == self.key_B)
        return self.key_A

# the below input takes about 22 seconds after the optimized modular exponentiation (exponentiation by squaring, taking care of overflows)
# ghost-3:c33 morpheus$ time python c33.py 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff 2
# shared diffie-hellman key : 805105511434234817106986926595494989866810339327377312979181972005995290578185931520565725456718580778696453045652905085817076596212923726135977803673852090949588518705019815870294926132352351830672879153487496328331245233441879385398902478357446638757874651668636292788986847545046740716823360545965348455809823394635959212364227754255575648614168629470365821766265667862205636092532195936039944527964343473441469117720499194092046380574967877438576124424487082

# real	0m22.014s
# user	0m21.773s
# sys	0m0.134s


if __name__ == "__main__":
    argc = len(sys.argv)
    if argc != 3:
        print "Usage: %s modulus (in hex) generator" % (sys.argv[0])
        exit(-1)
    
    # generate diffie-hellman shared key
    p = int(sys.argv[1], 16)
    g = int(sys.argv[2])

    dh = DiffieHellman(p, g)
    key = dh.get_dh_key()
    print "shared diffie-hellman key : %s" % (str(key))
    