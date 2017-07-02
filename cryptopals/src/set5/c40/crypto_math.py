


class CryptoMath:
    @staticmethod
    def egcd(a, n):
        t = 0
        newt = 1
        r = n
        newr = a
        while newr != 0:
            q = r // newr
            (t, newt) = (newt, t - q * newt)
            (r, newr) = (newr, r - q * newr)
        if t < 0:
            t += n
        return (r, t)

    @staticmethod
    def mod_inv(a, n):
        g, t = CryptoMath.egcd(a, n)
        if g!= 1:
            raise("modular inverse does not exist for %d in %d" % (a, n))
        else:
            return t % n

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

    @staticmethod
    def solve_crt(c, n, mod = True):
        k = len(c)
        assert(k == len(n))

        # compute overall modulus N
        N = 1
        for i in range(k):
            N = N * n[i]
        print "N : %d" % (N)

        # compute Zi 
        z = []
        for i in range(k):
            z.append(N/n[i])
        
        # compute Yi which is the inverse of Zi in Ni
        y = []
        for i in range(k):
            y.append(CryptoMath.mod_inv(z[i], n[i]))
        
        # compute w
        w = []
        for i in range(k):
            w.append(CryptoMath.mod_mul(y[i], z[i], N))
        
        # compute the result
        p = 0
        for i in range(k):
            p = p + (w[i] * c[i])
        
        if mod:
            p = p % N
        return p


if __name__ == "__main__":
    a = 17
    n = 3120
    print CryptoMath.mod_inv(a, n)