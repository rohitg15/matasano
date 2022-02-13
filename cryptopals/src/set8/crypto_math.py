
import sys
from typing import List, Optional
from Crypto import Random
import random
import math

class MyError(Exception):
    def __init__(self, value) -> None:
        self.value = value
    
    def __str__(self) -> str:
        return (repr(self.value))

class Point:
    """
        Represents a point on an elliptic curve
    """
    def __init__(self, x, y):
        self.x = x
        self.y = y
    
        
    def equals(self, other) -> bool:
        return (self.x == other.x and self.y == other.y)
    
    def __eq__(self, other: object) -> bool:
        return self.equals(other)
    

class CryptoMath:

    @staticmethod
    def get_random_bytes(n :int)    ->  bytes():
        """
            returns :   bytes()  n cryptographically random bytes
        """
        return Random.get_random_bytes(n)

    @staticmethod
    def get_prng_int(x :int, y :int)  ->  int:
        """
            returns :   (int)   a such that
            x <= a <= y
            and a is the output of a non-cryptographic pseudo-random generator
        """
        return random.randint(x, y)

    @staticmethod
    def mod_exp(x :int, y :int, n :int) -> int:
        """
            returns : (int) (x ** y) % n
        """
        res = 1
        while y > 0:
            if (y & 1) == 1:
                res = (res * x) % n
            x = (x * x) % n
            y = y >> 1

        return res % n
    
    @staticmethod
    def gcd(x :int, y :int) -> int:
        """
            returns :   (int)   gcd(x,y) using euclid's algorithm
        """
        while y > 0:
            x, y = y, x % y

        return x

    @staticmethod
    def egcd(x :int, y :int) -> int:
        """
            returns :   (int, int, int) : (d, a, b) such that
                d   :   gcd(x,y)    =   a*x + b*y
            using extended euclidean algorithm
        """
        a0 = 1
        b0 = 0
        a1 = 0
        b1 = 1
        r0 = x
        r1 = y
        while r1 > 0:
            q = r0 // r1
            r2 = r0 - q * r1
            a2 = a0 - q * a1
            b2 = b0 - q * b1

            r0 = r1
            r1 = r2
            a0 = a1
            a1 = a2
            b0 = b1
            b1 = b2
        
        return (r0, a0, b0)

    @staticmethod
    def mod_inv(x :int, n :int) -> int:
        """
            returns :   (int)   :   (y) such that
            (x * y) % n = 1
        """
        (d, a, b) = CryptoMath.egcd(x, n)
        if d != 1:
            # modular inverse does not exist
            return None
        if a < 0:
            return n + a
        return a
    
    @staticmethod
    def mod_mul(x :int, y :int, p :int) -> int:
        """
            returns (int)   :   product of x and y modulo p
        """
        res = 0
        while y > 0:
            if y & 1:
                res = (res + x) % p
            x = (x + x) % p
            y = y >> 1
        
        return res % p
        
    @staticmethod
    def fermat_is_prime(p :int) ->  bool:
        """
            returns :   (bool)  True if p is a prime
                according to the Fermat's primality test.
                This can be fooled by carmichael numbers eg: 561
        """
        assert(p > 1)
        if p == 2 or p == 3:
            return True
        
        a = CryptoMath.get_prng_int(2, p - 1)
        if CryptoMath.mod_exp(a, p - 1, p) == 1:
            return True
        return False
    
    @staticmethod
    def crt(a : List[int], n : List[int]) ->  int:
        """
            returns :   x (mod M) such that
            x % n[i] = a[i] for each (a[i], n[i])
            M = n[0] * n[1] .... * n[num - 1]
            where num = len(n) = len(a)
            assumes that n[i] is relatively prime with n[j] for all j != i
            computes 'x' using the chinese remainder theorem
        """
        num = len(n)
        assert(num == len(a))

        M = 1
        for i in range(num):
            M *= n[i]
        
        N = []
        for i in range(num):
            N.append(M // n[i])
        
        # now, gcd(N[i], n[i]) = 1
        z = []
        for i in range(num):
            z.append(CryptoMath.mod_inv(N[i], n[i]))
        
        x = 0
        # (z[i] * N[i]) % n[i] = 1
        # (z[i] * n[i]) % n[j] = 0 when j != i
        for i in range(num):
            x = (x + ( (a[i] * z[i] * N[i]) % M )) % M

        return x

    @staticmethod
    def get_primes(n :int) -> List[int]:
        """
            returns :   [(int)] array of primes <= n
                computed using the sieve method
        """

        primes = [True] * (n + 1)
        count = len(primes)
        res = []
        for p in range(2, count):
            if primes[p] is True:
                res.append(p)
                j = p * 2
                while j < count:
                    primes[j] = False
                    j = j + p

        return res
    
    @staticmethod
    def miller_rabin_is_prime(p :int, num_iterations : int = 5)   ->  bool:
        """
            returns :   (bool) True if p is a prime
                according to the Miller-Rabin primality test
        """
        assert(p > 1)
        if p == 2 or p == 3:
            return True
        
        q = p - 1
        s = 0
        while q > 0 and q % 2 == 0:
            s += 1
            q = q >> 1
        
        for _ in range(num_iterations):
            a = CryptoMath.get_prng_int(2, p  - 1)
            d = CryptoMath.mod_exp(a, q, p)
            if d == 1 or d == p - 1:
                # possibly prime, check next witness
                continue
            
            is_possibly_prime = False
            for i in range(1, s):
                d = pow(d, 2, p)
                if d == p - 1:
                    # possibly prime, check next witness
                    is_possibly_prime = True
                    break
            
            if is_possibly_prime is False:
                # definitely composite - a value y other than 1, p - 1 satisfied
                # pow (x, p - 1, p) = 1 such that y * y = x
                return False
        
        return True

    @staticmethod
    def phi(n : int) -> int:
        """
            returns :   (int)   euler's totient function on input n
        """
        if (n == 1):
            return 1

        i = 2
        result = n
        while i * i <= n:
            if n % i == 0:
                while n % i == 0:
                    n = n // i
                result = (result - (result // i))
            i = i + 1
        
        if n > 1:
            result = (result - (result // n))
        
        return result

    # Factorization Algorithms
    @staticmethod
    def fermat_factorization(n :int) -> int:
        """
            returns :   (int) a factor of n 
                computed using the Fermat's 2 squares method
        """
        a = math.ceil(math.sqrt(n))
        b2 = (a * a) - n
        b = int(math.sqrt(b2))
        while b2 != b * b:
            a = a + 1
            b2 = (a * a) - n
            b = int(math.sqrt(b2))

        return a - b

    @staticmethod
    def pollard_pminus1_factorization(n : int, b_max :int  = 1000000) -> int:
        """
            returns :   (int) a factor of n
                computed using the pollard's p-1 algorithm

                idea:   if n = p * q and p is a prime such that p - 1 is B-powersmooth,
                        then fermat's little theorem can be used to compute ((a ** M) - 1),
                        which has a gcd (>1) with n
        """
        b = 10
        primes = CryptoMath.get_primes(b_max)
        g = 1
        while b <= b_max and g < n:
            a = CryptoMath.get_prng_int(2, n - 1)
            g = CryptoMath.gcd(a, n)
            if (g > 1):
                return g
            
            for p in primes:
                if p >= b:
                    continue

                pe = 1
                while pe * p <= b:
                    pe = pe * p
                
                a = CryptoMath.mod_exp(a, pe, n)
                g = CryptoMath.gcd(a - 1, n)
                if g > 1 and g < n:
                    return g
            
            b = b * 2

        return 1

    @staticmethod
    def pollard_pminus1_factorization2(n :int, B :int = 1000000, iter = 100) -> int:
        """
            returns :   (int) a factor of n computed using pollard's p-1 algorithm
        """
        for _ in range(iter):
            a = CryptoMath.get_prng_int(2, n-1)
            g = CryptoMath.gcd(a, n)
            if g > 1:
                return g
            
            for i in range(2, B):
                a = CryptoMath.mod_exp(a, i, n)
                g = CryptoMath.gcd(a - 1, n)
                if g > 1 and g < n:
                    return g
        
        return 1


    @staticmethod
    def pollards_rho_factorization(n :int, rseed = 2) -> int:
        """
            returns :   (int) a factor of n
                computed using pollard's rho algorithm
        """
        def f(x :int) -> int:
            return (x * x + 1) % n
        
        g = 1
        seed = rseed
        x = seed
        y = seed
        while g == 1:
            x = f(x)
            y = f(y)
            y = f(y)

            # key idea: x = y mod p (but not mod n)
            g = CryptoMath.gcd(x - y, n)
        
        return g

    # Discrete Logarithm Algorithms

    # @staticmethod
    # def baby_step_giant_step_dlog(a :int, b : int, m :int) -> int:
    #     """
    #         returns :   (int)   x such that
    #             (a ** x) mod m = b using baby-step-giant-step algorithm
    #             consider x = np + q
    #     """
    #     n = int(math.sqrt(m)) + 1
    #     table = {}
    #     g = pow(a, n, m)
    #     for p in range(1, n + 1):
    #         table[g] = p
    #         g = (g * a) % m
        
    #     g = b % m
    #     for q in range(0, n + 1):
    #         exp_p  = table.get(g)
    #         if exp_p is not None:
    #             res = (n * exp_p - q)
    #             if res < m:
    #                 return res
    #         g = (g * a) % m
        
    #     return -1

    

    # @staticmethod
    # def pollards_rho_dlog(g :int, y :int, n: int) -> int:
    #     """
    #         returns :   (int)   x such that
    #             (g ** x) mod n = y using pollard's rho algorithm
    #             idea: find a collision in the sequence (g ** ai)(y ** bi) = (g ** aj)(y ** bj)
    #             n   : prime
    #     """
    #     m = n - 1
    #     h = (g * y) % n
    #     def f(x :int, g :int, y :int, n :int, a :int, b :int) -> (int, int, int):
    #         res = x % 3
    #         if res == 0:
    #             return ( (x * g) % n, a + 1, b )
    #         elif res == 1:
    #             return ( (x * x) % n, a + 1, b + 1)
    #         return ( (x * y) % n, a, b + 1 )
        
    #     ai = bi = aj = bj = 1
    #     slow = h
    #     fast = h
    #     while True:
    #         slow, ai, bi = f(slow, g, y, n, ai, bi)
    #         fast, aj, bj = f(fast, g, y, n, aj, bj)
    #         fast, aj, bj = f(fast, g, y, n, aj, bj)
    #         if slow == fast:
    #             a = (ai - aj) % m
    #             b = (bj - bi) % m
    #             b_inv = CryptoMath.mod_inv(b, m)
    #             if b_inv is None:
    #                 raise('Error: hit corner case in pollards rho')
    #             return (a * b_inv) % m
            
    #     return None
    

    @staticmethod
    def get_nth_root(a : int, n : int, e : int = 0) -> int:
        """
            returns n'th root of a computed using 
            newton's method

            f(x) = (x ** n) - a
            f'(x) = n * (x ** (n - 1))
        """
        # guess initial x
        x_cur = random.randint(1, a)
            
        while abs(pow(x_cur, n) - a) > e:
            y_cur = (x_cur ** n) - a
            m = n * int(pow(x_cur, n - 1))
            
            x_next = (m * x_cur - y_cur) // m
            x_cur = x_next
        
        return int(x_cur)

    
    # Discrete logarithm algorithms

    @staticmethod
    def dh_baby_step_giant_step(y : int , g : int, p : int) -> int:
        """
            return x such that y = (g ** x) mod p

            uses baby step giant step algorithm - 
                let x = im + j
                where m = sqrt(n) where n = order of the group
                we precompute (g ** j) % p

        """
        n = p - 1
        m = int(math.sqrt(n))
        table = {pow(g, j, p) : j for j in range(m)}
        
        g = pow(g, m, p)
        g = pow(g, p - 2, p)
        h = 1
        for i in range(m):
            h = (y * pow(g, i, p) ) % p
            j = table.get(h)
            if j is not None:
                return i * m + j
        
        return None

    
    @staticmethod
    def pollards_rho_dlog(y : int, g : int, p : int) -> int:
        """
            return x such that y = (g ** x) mod p

            uses pollard's rho algorithm to identify a
            collision in the sequence (g ^ a) * (y ^ b) 
            using a pseudorandom walk.

        """
        n = p - 1
        h = g * y
        def f(x : int, a : int, b : int) -> int:
            res = x % 3
            if res == 0:
                return ( (x * g) % p, (a + 1) % n, b)
            elif res == 1:
                return ( (x * x) % p, (a * 2) % n, (b * 2) % n )
            else:
                return ( (x * y) % p, a, (b + 1) % n)
        
        slow = h
        a0 = 1
        b0 = 1

        fast = h
        a1 = 1
        b1 = 1

        while True:
            slow, a0, b0 = f(slow, a0, b0)
            fast, a1, b1 = f(fast, a1, b1)
            fast, a1, b1 = f(fast, a1, b1)

            if slow == fast:
                b_diff = (b0 - b1) % n
                a_diff = (a1 - a0) % n
                b_inv = CryptoMath.mod_inv(n, b_diff)
                if b_inv is None:
                    print (slow, fast, b_diff, n)
                    raise Exception('polalrds rho failed since modular inverse could not be computed')
                return (a_diff * b_inv) % n
        
    @staticmethod
    def pollards_kangaroo_dlog(y : int, g : int, p : int, a : int, b : int, num_trials : int = 100) -> int:
        """
            returns x such that y = (g ** x) mod p

            using pollard's kangaroo algorithm when we know that
            a <= x <= b

            if mean jump length is c, then probability of collision
            after N jumps is 1 - (1 - 1 / c) ^ N
            which approximates to 1 - e ^ 1 / 4 when N = 4c
            which is roughly 0.98

            c = 2 ** k / k
        """

        k = int( math.log2( (b - a) // 2 ) )
        N = int(4 * pow(2, k + 2) // k) + 1
        order = p - 1

        for i in range(num_trials):
            # start tame kangaroo
            tame = b + i
            for _ in range(N):
                tame = ( tame + pow(2, pow(g, tame, k), order) ) % order
            
            yn = pow(g, tame, p)
            
            # start wild kangaroo
            wild = y
            d = 0
            while True:
                leap = pow(2, wild, k)
                d += leap
                wild = ( wild * pow(g, leap, p) ) % p

                if d > tame - a:
                    break

                if wild == yn:
                    return tame - d
        
        return None

    @staticmethod
    def lenstra_ecm_factorization(n: int, b_max: int = 100000, num_iterations = 100) -> int:
        """
            returns :   (int) factor of n, computed using
                        Lenstra's elliptic curve factorization method

                        Considering standard weirstrass curve
                        y^2 = x^3 + Ax + B (mod N)
        """

        for _ in range(num_iterations):

            # choose point P = (a, b) and then A, B all mod n
            a = random.randint(1, n - 1)
            b = random.randint(1, n - 1)
            P = Point(a, b)

            A = random.randint(1, n - 1)
            B = (b ** 2 - (a ** 3 + A * a)) % n
            
            # choosing the point first, then A and then B ensures the 
            # point (a, b) lies on the curve

            curve = EllipticCurve(A, B, n)

            Q = P
            for j in range(2, b_max):
                try:
                    Q = curve.scale(Q, j)
                except MyError as ex:
                    e = int(ex.__str__())
                    d = CryptoMath.gcd(e, n)
                    if d > 1 and d < n:
                        return d
                    if d == n:
                        break

        return None


    @staticmethod
    def modular_sqrt(a, p):
    
        a %= p

        # Simple case
        if a == 0:
            return 0
        if p == 2:
            return a

        # Check solution existence on odd prime
        if CryptoMath.legendre_symbol(a, p) != 1:
            return None

        # Simple case
        if p % 4 == 3:
            x = pow(a, (p + 1) // 4, p)
            if x > 0:
                return x
            return p + x
            
        # Factor p-1 on the form q * 2^s (with Q odd)
        q, s = p - 1, 0
        while q % 2 == 0:
            s += 1
            q //= 2

        # Select a z which is a quadratic non resudue modulo p
        z = 1
        while CryptoMath.legendre_symbol(z, p) != -1:
            z += 1
        c = pow(z, q, p)

        # Search for a solution
        x = pow(a, (q + 1) // 2, p)
        t = pow(a, q, p)
        m = s
        while t != 1:
            # Find the lowest i such that t^(2^i) = 1
            i, e = 0, 2
            for i in range(1, m):
                if pow(t, e, p) == 1:
                    break
                e *= 2

            # Update next value to iterate
            b = pow(c, 2**(m - i - 1), p)
            x = (x * b) % p
            t = (t * b * b) % p
            c = (b * b) % p
            m = i

        if x > 0:
            return x
        return p + x

    @staticmethod
    def modular_sqrt2(a, p):
        """ Find a quadratic residue (mod p) of 'a'. p
            must be an odd prime.

            Solve the congruence of the form:
                x^2 = a (mod p)
            And returns x. Note that p - x is also a root.

            0 is returned is no square root exists for
            these a and p.

            The Tonelli-Shanks algorithm is used (except
            for some simple cases in which the solution
            is known from an identity). This algorithm
            runs in polynomial time (unless the
            generalized Riemann hypothesis is false).
        """
        # Simple cases
        #
        if CryptoMath.legendre_symbol(a, p) != 1:
            return 0
        elif a == 0:
            return 0
        elif p == 2:
            return 0
        elif p % 4 == 3:
            return pow(a, (p + 1) // 4, p)

        # Partition p-1 to s * 2^e for an odd s (i.e.
        # reduce all the powers of 2 from p-1)
        #
        s = p - 1
        e = 0
        while s % 2 == 0:
            s /= 2
            e += 1

        # Find some 'n' with a legendre symbol n|p = -1.
        # Shouldn't take long.
        #
        n = 2
        while CryptoMath.legendre_symbol(n, p) != -1:
            n += 1

        # Here be dragons!
        # Read the paper "Square roots from 1; 24, 51,
        # 10 to Dan Shanks" by Ezra Brown for more
        # information
        #

        # x is a guess of the square root that gets better
        # with each iteration.
        # b is the "fudge factor" - by how much we're off
        # with the guess. The invariant x^2 = ab (mod p)
        # is maintained throughout the loop.
        # g is used for successive powers of n to update
        # both a and b
        # r is the exponent - decreases with each update
        #
        x = pow(a, (s + 1) // 2, p)
        b = pow(a, s, p)
        g = pow(n, s, p)
        r = e

        while True:
            t = b
            m = 0
            for m in range(r):
                if t == 1:
                    break
                t = pow(t, 2, p)

            if m == 0:
                return x

            gs = pow(g, 2 ** (r - m - 1), p)
            g = (gs * gs) % p
            x = (x * gs) % p
            b = (b * g) % p
            r = m

    @staticmethod
    def legendre_symbol(a, p):
        """ Compute the Legendre symbol a|p using
            Euler's criterion. p is a prime, a is
            relatively prime to p (if p divides
            a, then a|p = 0)

            Returns 1 if a has a square root modulo
            p, -1 otherwise.
        """
        ls = pow(a, (p - 1) // 2, p)
        return -1 if ls == p - 1 else ls
    

    @staticmethod
    def next_prime(n :int) -> int:
        """
            Returns the next prime number > n
        """

        # Bertrand's postulate states that for n > 3,
        # there is at least one prime between (n, 2*n - 2)
        for i in range(n + 1, 2 * n):
            if CryptoMath.miller_rabin_is_prime(i) is True:
                return i
        
        raise Exception('Failed to find prime > {0}'.format(n))




class EllipticCurve:
    """
        Represents an elliptic curve
    """
    def __init__(self, a, b, p, curve_order = None):
        """
            a - curve x-coefficient of type integer
            b - curve constant of type integer
            curve_order - number of elements defined by this elliptic curve group
            p - modulus for the finite field of type integer
        """
        self.curve_order = curve_order
        self.O = Point(0, 1)
        self.p = p
        if a < 0:
            self.a = p + a
        else:
            self.a = a
        if b < 0:
            self.b = p + b
        else:
            self.b = b
        
        self.subgroups = []
    
    @staticmethod
    def next_power_of_2(x):
        return 1 if x == 0 else 2**math.ceil(math.log2(x))

    def get_random_point(self):
        x = y = -1
        x = 2
            
        while True:
            x = random.randint(2, self.p)
            # x = Random.get_random_bytes( int( math.log2( EllipticCurve.next_power_of_2(self.p) ) ) >> 3 )
            # x = int.from_bytes(x, 'big')
            ysq = ( (x * x * x) + (self.a * x) + self.b ) % self.p
            y = CryptoMath.modular_sqrt(ysq, self.p)
            if y is not None:
                break
            
        print ("Found random point on curve: -> (", x, " , ", y, ")")
        if y < 0:
            y = self.p + y
        return Point(x, y)
    

    def get_point_with_order(self, t :int) -> Point:
        """
            returns a point on the curve with order t
        """
        if (self.curve_order % t != 0):
            emsg = 't = {0} must divide curve order = {1}'.format(t, self.curve_order)
            raise Exception(emsg)
        
        k = self.curve_order // t
        while True:
            G = self.get_random_point()
            G = self.scale(G, k)
            print (G.x, G.y)
            if G.equals(self.O) is False:
                return G


    
    
    def add_subgroup(self, sg, sg_order):
        self.subgroups.append(Subgroup(sg, sg_order))
    
    def __inverse__(self, p):
        """
            returns inverse of point p on the Elliptic Curve in GF(p)
        """
        return Point(p.x, (self.p + (-1 * p.y)) % self.p)


    def valid(self, P):
        """
            Determine whether we have a valid representation of a point
            on our curve.  We assume that the x and y coordinates
            are always reduced modulo p, so that we can compare
            two points for equality with a simple ==
        """
        if P == self.O:
            return True
        else:
            return (
                (P.y**2 - (P.x**3 + self.a*P.x + self.b)) % self.p == 0 and
                0 <= P.x < self.p and 0 <= P.y < self.p)
        
    def add(self, p1, p2):
        """
            Add two points p1, p2 in GF(p)

            Arguments-
                p1  -   point on the Elliptic Curve
                p2  -   point on the Elliptoc Curve
            
            Returns-
                point obtained by adding the points p1 and p2

        """
        if p1.equals(self.O):
            return p2

        if p2.equals(self.O):
            return p1

        p2_inv = self.__inverse__(p2)
        if p1.equals(p2_inv):
            return self.O

        x1 = p1.x
        y1 = p1.y

        x2 = p2.x
        y2 = p2.y

        if p1.equals(p2):
            y1_inv = CryptoMath.mod_inv(y1 * 2, self.p)
            if y1_inv is None:
                raise MyError(y1 * 2)
            m = CryptoMath.mod_mul(  (3 * x1 * x1 + self.a), y1_inv, self.p )
        else:
            x_diff = (x2 - x1)
            x_inv = CryptoMath.mod_inv(x_diff, self.p)
            if x_inv is None:
                raise MyError(x_diff)
            y_diff = y2 - y1
            m = CryptoMath.mod_mul( y_diff, x_inv, self.p )

        x3 = (m**2 - x1 - x2) % self.p

        y3 = (m * (x1 - x3) - y1) % self.p
        
        # assert(self.valid(new_p))
        return Point(x3, y3)

    def scale(self, x :Point, k :int):
        """
            compute scalar product x * k

            Arguments-
                x   -   point on the Elliptic Curve
                k   -   scalar integer
            
            Returns-
                Summation of x with itself k times
        """
        result = self.O
        while k > 0:
            if k & 1:
                result = self.add(result, x)
            x = self.add(x, x)
            k = k >> 1
        return result

    


if __name__ == "__main__":
    # print ("mod_exp (2, 7, 11) : ", CryptoMath.mod_exp(2, 7, 11))
    # print ("gcd (1, 0) : ", CryptoMath.gcd(1, 0))
    # print ("gcd (0, 1) : ", CryptoMath.gcd(0, 1))
    # print ("gcd (0, 0) : ", CryptoMath.gcd(0, 0))
    # print ("gcd (10, 5): ", CryptoMath.gcd(10, 5))
    # print ("gcd (12, 16): ", CryptoMath.gcd(12, 16))
    # print ("egcd (12, 16):", CryptoMath.egcd(12, 16))
    # print ("egcd (65537, 18)", CryptoMath.egcd(65537, 18) )
    # print ("mod_inv(18, 65537): ", CryptoMath.mod_inv(18, 65537))
    # print ("fermat_is_prime(2): ", CryptoMath.fermat_is_prime(2))
    # print ("fermat_is_prime(3): ", CryptoMath.fermat_is_prime(3))
    # print ("fermat_is_prime(7): ", CryptoMath.fermat_is_prime(7))
    # print ("fermat_is_prime(11): ", CryptoMath.fermat_is_prime(11))
    # print ("fermat_is_prime(13): ", CryptoMath.fermat_is_prime(13))
    # print ("fermat_is_prime(1105): ", CryptoMath.fermat_is_prime(1105))
    # print ("miller_rabin_is_prime(2): ", CryptoMath.miller_rabin_is_prime(2))
    # print ("miller_rabin_is_prime(3): ", CryptoMath.miller_rabin_is_prime(3))
    # print ("miller_rabin_is_prime(7): ", CryptoMath.miller_rabin_is_prime(7))
    # print ("miller_rabin_is_prime(11): ", CryptoMath.miller_rabin_is_prime(11))
    # print ("miller_rabin_is_prime(13): ", CryptoMath.miller_rabin_is_prime(13))
    # print ("miller_rabin_is_prime(1105): ", CryptoMath.miller_rabin_is_prime(1105))
    # print ("crt ([1, 4, 6], [3, 5, 7]): ", CryptoMath.crt([1, 4, 6], [3, 5, 7]))
    # print ("phi(1): ", CryptoMath.phi(1))
    # print ("phi(2): ", CryptoMath.phi(2))
    # print ("phi(15): ", CryptoMath.phi(15))
    # print ("fermat_factorization(15): ", CryptoMath.fermat_factorization(15))
    # print ("fermat_factorization(121): ", CryptoMath.fermat_factorization(121))
    # print ("fermat_factorization(13273)", CryptoMath.fermat_factorization(13273))
    # print ("pollard_pminus1_factorization(4817191, 1000): ", CryptoMath.pollard_pminus1_factorization2(4817191, 100000))
    # print ("pollard_pminus1_factorization(121, 100): ", CryptoMath.pollard_pminus1_factorization2(121, 100))
    # print ("pollard_pminus1_factorization(1024, 100): ", CryptoMath.pollard_pminus1_factorization2(1024, 100))
    # print ("pollard_pminus1_factorization(65537, 100000): ", CryptoMath.pollard_pminus1_factorization2(65537, 100000))
    # print ("pollard_rho_factorization(4817191): ", CryptoMath.pollards_rho_factorization(4817191))
    # print ("baby_step_giant_step_discrete_logarithm(2, 3, 5): ", CryptoMath.baby_step_giant_step_dlog(2, 3, 5))
    #print ("pollards_rho_discrete_log(2, 3, 5): ", CryptoMath.pollards_rho_dlog(2, 13699544328167240935, 16429744134624869189))
    # print ("pollards kangaroo discrete log = ", CryptoMath.pollards_kangaroo_dlog(60316, 3, 65537, 38000, 60000))

    # print ("pollards kangaroo discrete log = ", CryptoMath.pollards_kangaroo_dlog(7760073848032689505395005705677365876654629189298052775754597607446617558600394076764814236081991643094239886772481052254010323780165093955236429914607119, 622952335333961296978159266084741085889881358738459939978290179936063635566740258555167783009058567397963466103140082647486611657350811560630587013183357, 11470374874925275658116663507232161402086650258453896274534991676898999262641581519101074740642369848233294239851519212341844337347119899874391456329785623, 1, 2 ** 20))

    print (CryptoMath.next_prime(45361))
    
    
