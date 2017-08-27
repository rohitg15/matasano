import sys
from Crypto.PublicKey import RSA
from Crypto.Util.number import getPrime
from crypto_math import CryptoMath
import base64

class ParityOracle:
    def __init__(self, rsa_key):
        self.rsa_key = rsa_key

    def is_decryption_valid(self, decrypted_plaintext):
        dm = int( decrypted_plaintext.encode('hex'), 16 )
        return ( ( dm & 1 ) == 0)

    def encrypt(self, message):
        return self.rsa_key.encrypt( message, None )

    def decrypt(self, ciphertext):
        decrypted_plaintext = self.rsa_key.decrypt( ciphertext )
        return ( self.is_decryption_valid(decrypted_plaintext), decrypted_plaintext )

def get_num_bits(x):
    count = 0
    while x != 0:
        count = count + 1
        x = x // 2
    return count

def binary_search(ct, p):
    lo = 0
    hi = p.rsa_key.n
    c = int( ct.encode( 'hex' ), 16 )
    prod = CryptoMath.mod_exp( 2, p.rsa_key.e, p.rsa_key.n )
    c = CryptoMath.mod_mul( c, prod, p.rsa_key.n ) 
    num_bits = get_num_bits(c)

    while num_bits > 0 and lo < hi :
        mid = lo + ( ( hi - lo ) // 2 )
        cipher = CryptoMath.lint_to_hex_str( c )
        ciphertext = cipher.decode( 'hex' )        
        is_even, _ = p.decrypt( ciphertext )
        # use parity to determine whether or not the plaintext
        # wraps the modulus, and search the corresponding half
        if is_even:
            hi = mid
        else:
            lo = mid
        
        dec = CryptoMath.lint_to_hex_str( hi )
        print dec.decode( 'hex' )

        # multiply c
        c = CryptoMath.mod_mul( c, prod, p.rsa_key.n ) 
        num_bits = num_bits - 1
    return hi


if __name__ == "__main__":
    argc = len( sys.argv )
    if argc != 2:
        print "usage: %s rsa_size_bits" % ( sys.argv[0] )
        exit(0)

    num_bits = int( sys.argv[1] )
    rsa_key = RSA.generate( num_bits, e=65537 )

    p = ParityOracle( rsa_key )

    m = "hello world!"
    assert( m == p.decrypt( p.encrypt( m )[0] )[1] )

    msg_b64 = "VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=="
    msg = base64.b64decode(msg_b64)

    ct = p.encrypt(msg)
    binary_search(ct[0], p)

    