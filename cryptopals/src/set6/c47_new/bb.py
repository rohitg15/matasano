import sys
from oracle import RsaOracle, RsaException
from random import randint
from crypto_math import CryptoMath
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
        while (k % 8 != 0):
            k = k + 1
        k = ((k / 8) - 2) * 8
        self.B = 2 ** (k)
        self.result = []

        print ("B            : ", self.B)
        print ("Blocksize    : ", self.blockSize)

    def get_prod_exp(self, c, s):
        """
            Returns :   c * (s ^ e) % n
        """
        tmp = CryptoMath.mod_exp(s, self.e, self.n)
        return CryptoMath.mod_mul(c, tmp, self.n)

    def step_1(self):
        """
            Blinding the RSA ciphertext until we get a PKCS#1.5 conforming plaintext

            Returns :
        """
        print ("Step 1 : Blinding")
        message = None
        while True:
            self.si = self.si + 1
            self.c0 = CryptoMath.get_int_from_bytearray(self.ciphertext.encode()) 
            p = BleichenBackerAttacker.get_prod_exp(self.c0, self.si)
            message = RsaOracle.prepare_msg(p)
            isValid = self.rsaOracle.get_response(message)
            if isValid: # message is PKCS#1.5 conforming
                break
        
        # update valus of c0, s0
        self.c0 = CryptoMath.int_from_bytes(message)
        self.s0 = self.si
        self.M = [(2 * self.B, (3 * self.B) - 1 )]

        print ("Found s0 : ", self.s0)

    def step_2A(self):
        """
            Searches for a si >= Ceil(n / 3B) until we get
            a PKCS#1.5 conforming message
        """
        print ("Step 2.A : begin search")
        self.si = math.ceil(n / (3 * self.B))

        while True:
            # Test oracle with current value of si
            t = self.get_prod_exp(self.c0, self.si)
            message = RsaOracle.prepare_message(t)
            isValid = self.rsaOracle.get_response(message)
            if isValid:
                break               # current value of si must be stored
            self.si = self.si + 1   # si updated only when oracle reports Failure
    
    def step_2B(self):


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
            self.c0 = CryptoMath.get_int_from_bytearray(self.ciphertext.encode())
            self.M.append((2 * self.B , (3 * self.B) - 1 ))
        else :
            self.step_1()
        
        i = i + 1
        while found is False:
            print ("Step 2 : Search for PKCS#1.5 conforming messages")
            self.step_2()

            print ("Step 3 : Narrow down solution set")
            self.step_3()

            print ("Step 4 : Compute final solution")
            found = self.step_4()

            i = i + 1
        
        return self.result

        
    

    
