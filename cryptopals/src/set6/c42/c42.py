import sys
import crypto_math
from Crypto.Util.number import getPrime
import hashlib
import math



class RSAValidatior:
    sha1oid = b'\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14' 
    
    @staticmethod
    def pad(m):
        return m

    @staticmethod
    def get_pkcs15_padded_msg(msg_hash):
        # we want a 128 byte (1024 bit) message. padding must contain 0x00 0x01 ... 0x00, hence the 3
        msg_hash_bytes = bytearray(msg_hash)
        num_ff_bytes = 128 - (len(msg_hash_bytes) + len(RSAValidatior.sha1oid) + 3)
        padding = b'\x00\x01' + (b'\xff' * num_ff_bytes) + b'\x00'
        padded_msg = padding + RSAValidatior.sha1oid + msg_hash_bytes
        assert(len(padded_msg) == 128)
        padded_msg_str = ''.join([chr(byte) for byte in padded_msg])
        padded_msg_hex = padded_msg_str.encode('hex')
        return padded_msg_hex


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

    def get_valid_signature(self, msg):
        msg_hash = hashlib.sha1(msg).digest()
        padded_msg_hex = RSAValidatior.get_pkcs15_padded_msg(msg_hash)

        #num_zeroes = (self.bits >> 3) - len(padded_msg)
        #padded_msg = padded_msg << (num_zeroes * 8)
        m = int(padded_msg_hex, 16)
        return self.rsa.decrypt(m)
    
    def verify_signature(self, msg, signature):
        
        expected_msg_hash = bytearray(hashlib.sha1(msg).digest())
        decoded_signature = self.rsa.encrypt(signature)
        # since the numbers are long, they have the 'L' suffix
        c = '000' + hex(decoded_signature)[2:-1]
        cbytes = bytearray(c.decode('hex'))
        
        # validate padding format 0x00 0x01 0xff .... 0xff
        if cbytes[0] != 0x00:
            return False
        if cbytes[1] != 0x01:
            return False
        if cbytes[2] != 0xff:
            return False
        i = 3

        while i < len(cbytes):
            if cbytes[i] != 0xff:
                break
            i = i + 1
        if cbytes[i] != 0x00:
            return False
        i = i + 1
        
        # check the SHA1oid here
        actual_sha1oid = cbytes[i : i + len(RSAValidatior.sha1oid)]
        for b0,b1 in zip(bytearray(RSAValidatior.sha1oid), actual_sha1oid):
            if b0 != b1:
                return False   
        i = i + len(RSAValidatior.sha1oid)
        
        # padding has been verified, extract the message digest from the bytearray
        actual_msg_hash = cbytes[i:i + len(expected_msg_hash)]
        # validate the received message digest
        is_valid = True
        for b0,b1 in zip(actual_msg_hash, expected_msg_hash):
            if b0 != b1:
                is_valid = False
        return is_valid


def get_forged_signature(msg):
    msg_digest = bytearray(hashlib.sha1(msg).digest())
    padded_msg = b'\x00\x01\xff\xff\xff\xff\x00' + RSAValidatior.sha1oid + msg_digest
    padded_msg_str = ''.join([chr(b) for b in padded_msg])
    m = int(padded_msg_str.encode('hex'), 16)
    remaining_bytes = 128 - len(padded_msg)

    # left-shift by the number of remaining bits (to fill up a 1024 bit integer)
    padded_msg_int = m << (remaining_bytes * 8)

    # get cube root of the forged inteer message to forge a signature
    forged_signature = crypto_math.CryptoMath.get_cube_root(padded_msg_int)
    return forged_signature


if __name__ == "__main__":
    msg = 'hi mom'
    rsa = RSAValidatior()
    original_signature = rsa.get_valid_signature(msg)
    forged_signature = get_forged_signature(msg)
    print "original signature : %d" % (original_signature)
    print "forged signature   : %d" % (forged_signature)
    if rsa.verify_signature(msg, forged_signature) == True:
        print "signature %s for message :  %s is valid" % (forged_signature, msg)
    else:
        print "signature %s for message :  %s is invalid" % (forged_signature, msg)
     