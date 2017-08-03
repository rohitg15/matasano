import sys
import crypto_math
from Crypto.Util.number import getPrime
import hashlib


class RSAValidatior:
    sha1oid = b'\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14' 
    
    @staticmethod
    def pad(m):
        return m

    def __init__(self, e = 3, bits = 1024):
        self.bits = bits
        self.e = e

        # generate p,q such that e does not divide
        # p-1 and q-1
        p = 1
        q = 1
        while (p % self.e) == 1:
            p = getPrime(self.bits)

        while (q % self.e) == 1:
            q = getPrime(self.bits)
        
        self.rsa = crypto_math.RSAHelper(p, q, self.e)

    def get_signature(self, msg):
        msg_hash = bytearray(hashlib.sha1(msg).digest())
        padding = b'\x00\x01\xff\xff\xff\xff\x00'
        padded_msg = padding + RSAValidatior.sha1oid + msg_hash
        num_zeroes = (self.bits >> 3) - len(padded_msg)
        padded_msg = padded_msg << (num_zeroes * 8)
        padded_msg_hex = padded_msg.encode('hex')
        m = int(padded_msg_hex, 16)
        return self.rsa.decrypt(m)
    
    def verify_signature(self, m, signature):
        pt = self.rsa.encrypt(signature)

        # incorrect padding validation here
        pt_bytes = bytearray(pt)
        if pt_bytes[:2] != b'\x00\x01':
            return False

        is_ff_present = False
        for byte in pt_bytes[2:]:
            if byte == 0xff:
                is_ff_present = True
                break
        if is_ff_present == False:
            return False
        
        # validate message bytes

if __name__ == "__main__":
