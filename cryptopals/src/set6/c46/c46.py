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

    print "num bits %d" % (num_bits)
    print c.bit_length()
    #return 



    while lo < hi :
        mid = lo + ( ( hi - lo ) // 2 )

        # convert integer to string
        cipher = hex( c )[2:-1]
        if len( cipher ) % 2 == 1:
            cipher = '0' + cipher
        ciphertext = cipher.decode( 'hex' )        
        is_even, _ = p.decrypt( ciphertext )
        if is_even:
            # did not wrap modulus
            hi = mid
        else:
            # wrapped modulus
            lo = mid
        
        dec = hex( hi )[2:-1]
        if len( dec ) % 2 == 1:
            dec = '0' + dec
        print dec.decode( 'hex' )

        # multiple c
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
    pt = binary_search(ct[0], p)
    for x in range(pt - 2000 , pt):
        dec = hex( x )[2:-1]
        if len( dec ) % 2 == 1:
            dec = '0' + dec
        print dec.decode( 'hex' )
        

    