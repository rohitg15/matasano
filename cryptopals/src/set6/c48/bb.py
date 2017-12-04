import sys
from oracle import RsaOracle
from random import randint
from crypto_math import CryptoMath
from RsaHelper import CryptographicException
import math

# class implementing BleichenBacker's attack
# on RSA PKCS1.5 encryption
class BleichenBackerAttacker:
    def __init__(self, rsaOracle, ciphertext, isMsgPkcs):
        """
            Initialize BleichenBacker's attack

            rsaOracle       :   Represents an abstract RSA PKCS#1.5 decryption oracle
            ciphertext      :   Represents an RSA encrypted ciphertext
            isMsgPkcs       :   Boolean indicating whether ciphertext's original message
                                is expected to be PKCS#1.5 conforming
        """
        self.rsaOracle = rsaOracle          #   Exposes the RSA padding oracle
        self.ciphertext = ciphertext  #   RSA PKCS1.5 encrypted message as integer
        
        self.publicKey = self.rsaOracle.get_public_key()
        self.n = self.publicKey.n           #   RSA public modulus
        self.e = self.publicKey.e           #   RSA public exponent

        self.isMsgPkcs = isMsgPkcs          #   Is original Msg PKCS1.5 conforming?

        self.c0 = 0
        self.s0 = 0
        self.si = 0
        self.M = []                         #   List of tuples representing search intervals
        self.blockSize = self.n.bit_length() // 8

        k = self.n.bit_length()
        #print ("num bits ", k)
        while (k % 8 != 0):
            k = k + 1
        k = ((k // 8) - 2) * 8
        #print ("new k : ", k)
        self.B = 2 ** k
        #print ("self.B = ", self.B)
        self.result = []

        #print ("B            : ", self.B)
        print ("Blocksize    : ", self.blockSize)

    def get_prod_exp(self, c, s):
        """
            Returns :   c * (s ^ e) % n
        """
        tmp = CryptoMath.mod_exp(s, self.e, self.n)
        return CryptoMath.mod_mul(c, tmp, self.n)


    @staticmethod
    def get_2c_upper_bound(r, n, a, B):
        return (3 * B + r * n) // a

    @staticmethod
    def get_2c_lower_bound(r, n, b, B):
        return (2 * B + r * n) // b

    @staticmethod
    def get_3_upper_bound(s, n, u, B):
        ub = u * s - 2 * B
        if ub % n == 0:
            return ub // n
        return (ub // n) + 1
    
    @staticmethod
    def get_3_lower_bound(s, n, l, B):
        lb = l * s - 3 * B
        return (lb + 1) // n


    def step_1(self):
        """
            Blinding the RSA ciphertext until we get a PKCS#1.5 conforming plaintext

            Returns :
        """
        print ("Step 1 : Blinding")
        message = None
        while True:
            self.si = self.si + 1
            self.c0 = CryptoMath.int_from_bytes(self.ciphertext) 
            p = self.get_prod_exp(self.c0, self.si)
            message = RsaOracle.prepare_message(p)
            isValid = self.rsaOracle.get_response(message)
            if isValid: # message is PKCS#1.5 conforming
                break
        
        # update valus of c0, s0
        self.c0 = CryptoMath.int_from_bytes(message)
        self.s0 = self.si
        self.M = [(2 * self.B, (3 * self.B) - 1 )]

        print ("Found s0 : ", self.s0)
        print ("Found c0 : ", self.c0)

    def step_2A(self):
        """
            Searches for a si >= Ceil(n / 3B) until we get
            a PKCS#1.5 conforming message
        """
        print ("Step 2.A : begin search")

        # Ceil(n, 3*B)
        
        self.si = self.n
        temp = 3 * self.B
        if self.si % temp != 0:
            self.si = (self.si // temp) + 1
        else:
            self.si = (self.si // temp)
        print ("Si  :   ", self.si)

        while True:
            # Test oracle with current value of si
            t = self.get_prod_exp(self.c0, self.si)
            message = RsaOracle.prepare_message(t)
            isValid = self.rsaOracle.get_response(message)
            if isValid:
                break               # current value of si must be stored
            self.si = self.si + 1   # si updated only when oracle reports Failure
            #print (self.si)
    
    def step_2B(self):
        """
            Search for si when M contains more than 1 interval
        """
        print ("Step 2.B : Searching with more than 1 interval in M")

        while True:
            self.si = self.si + 1
            t = self.get_prod_exp(self.c0, self.si)
            message = RsaOracle.prepare_message(t)
            isValid = self.rsaOracle.get_response(message)
            if isValid:
                break
    
    def step_2C(self):
        """
            Search for si when M contains only 1 interval
        """
        print ("Step 2.C : Search for si with 1 interval in M")

        ri = (2 * (self.si * self.M[0][1] - 2 * self.B) ) // self.n

        ub = BleichenBackerAttacker.get_2c_upper_bound(ri, self.n, self.M[0][0], self.B)
        lb = BleichenBackerAttacker.get_2c_lower_bound(ri, self.n, self.M[0][1], self.B)
        self.si = lb

        while True:
            if self.si > ub:
                ri = ri + 1
                ub = BleichenBackerAttacker.get_2c_upper_bound(ri, self.n, self.M[0][0], self.B)
                lb = BleichenBackerAttacker.get_2c_lower_bound(ri, self.n, self.M[0][1], self.B)
                self.si = lb
            t = self.get_prod_exp(self.c0, self.si)
            message = RsaOracle.prepare_message(t)
            isValid = self.rsaOracle.get_response(message)
            if isValid:
                break
            self.si = self.si + 1

    def step_2(self, i):
        """
            Wrapper method for invoking the 3 sub-parts of 
            Bleichenbacker's step 2, to search for PKCS#1.5
            conforming messages
        """
        if i == 1:
            self.step_2A()
        else:
            if (i > 1) and (len(self.M) >= 2):
                self.step_2B()
            elif len(self.M) == 1:
                self.step_2C()
        
        print ("Found s", i, self.si)

    def step_3(self):
        """
            Narrowing the set of solutions given si
        """
        intervals = []
        for m in self.M:
            ub = BleichenBackerAttacker.get_3_upper_bound(self.si, self.n, m[1], self.B)
            lb = BleichenBackerAttacker.get_3_lower_bound(self.si, self.n, m[0], self.B)

            r = lb
            while r <= ub:
                # Ceil((2*B + r*n), si)
                maxVal = (2 * self.B + r * self.n)
                if ( (maxVal % self.si) != 0 ):
                    maxVal = (maxVal // self.si) + 1
                else:
                    maxVal = (maxVal // self.si)
                
                # Floor((3*B - 1 + r*n), si)
                minVal = (3 * self.B - 1 + r * self.n) // self.si

                # create interval
                if m[0] > maxVal:
                    maxVal = m[0]
                if m[1] < minVal:
                    minVal = m[1]
                if maxVal <= minVal:
                    intervals.append((maxVal, minVal))
                r = r + 1
        print ("Finished step 3. Number of intervals found = ", len(intervals))
        return intervals

    def step_4(self):
        """
            Compute final solution from a single interval with repeated elements
        """
        if len(self.M) != 1:
            print("Step 4 found M with " + str(len(self.M)) + " intervals. Expected only 1 interval, returning False.")
            return False

        interval = self.M[0]
        if interval[0] != interval[1]:
            print("Step 4 encountered interval with unequal elements " + str(interval[0]) + " and " + str(interval[1]) + " , returning False.")
            return False
        
        print ("Step 4 : Converged at element ", interval[1])
        print ("Step 4: computing modular inverse of " + str(self.s0) + " mod " + str(self.n))
        sInv = CryptoMath.mod_inv(self.s0, self.n)
        mInt = CryptoMath.mod_mul(sInv, interval[1], self.n)
        self.result = mInt
        return True


    def attack(self):
        """
            Driver function for executing Bleichenbacker's attack against the 
            rsaOracle supplied initially and executes the 4 steps involved in
            Bleichenbacker's attack.

            Returns :   original plaintext message after stripping out the 
                        PKCS#1.5 padding
        """
        i = 0
        found = False

        if ( self.isMsgPkcs ):
            print ("Message is PKCS#1.5 conforming. Skipping step 1")
            self.so = 1
            self.c0 = CryptoMath.int_from_bytes(self.ciphertext)
            self.M.append((2 * self.B , (3 * self.B) - 1 ))
        else :
            self.step_1()
        print ("C0  :   ", self.c0)
        i = i + 1
        while found is False:
            print ("Step 2 : Search for PKCS#1.5 conforming messages")
            self.step_2(i)

            print ("Step 3 : Narrow down solution set")
            intervals = self.step_3()
            self.M = intervals

            print ("Step 4 : Compute final solution")
            found = self.step_4()

            i = i + 1
        
        print (self.result)
        print (CryptoMath.int_to_bytes(self.result))
        return self.result

        
    

    
