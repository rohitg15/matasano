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

