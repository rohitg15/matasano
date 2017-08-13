import sys
from crypto_math import CryptoMath
import hashlib


class SignedMessage:
    """ encapsulates a message, DSA signature"""
    def __init__(self, msg, s, r, m):
        self.msg = msg
        self.s = s
        self.r = r
        self.m = m


def get_k(m1, m2, s1, s2, q):
    k = CryptoMath.mod_mul(m1 - m2, 1, q)
    s = CryptoMath.mod_mul(s1 - s2, 1, q)
    s_inv = CryptoMath.mod_inv(s, q)
    k = CryptoMath.mod_mul(k, s_inv, q)
    return k

def get_x_from_known_k(k, h, q, r, s):
    
    # x = s * k - H(msg) mod q
    #     --------------
    #           r
    r_inv = CryptoMath.mod_inv(r, q)
    x = CryptoMath.mod_mul(s, k, q) - h
    x = CryptoMath.mod_mul(x, r_inv, q)
    return x


if __name__ == "__main__":
    argc = len(sys.argv)
    if argc != 2:
        print "usage: %s filename" % (sys.argv[0])
        exit(0)
    p = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1
    q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
    g = 0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291
    expected_hash = "ca8f6f7c66fa362d40760d135b763eb8527d3d52"
    filename = sys.argv[1]
    with open(filename, "r") as file:
        lines = file.read().strip('\n').split('\n')
    
    # group every 3 lines into a single signed message
    message_table = {}
    num_lines = len(lines)
    for i in range(0, num_lines, 4):
        msg = lines[i][len("msg: "):]
        s = int(lines[i + 1][len("s: "):])
        r = int(lines[i + 2][len("r: "):])
        m = int(lines[i + 3][len("m: "):], 16)
        signed_message = SignedMessage(msg, s, r, m)
        
        # since r collides when k collides, build a hash table based on r
        if message_table.has_key(r) == False:
            message_table[r] = []
        message_table[r].append(signed_message)
    
    # ks1 = m1 + xr mod q
    # ks2 = m2 + xr mod q
    # NOTE: since k collides for 2 messages, r = g ** k mod p mod q is also the same
    # Therefore k = (m1 - m2) * (s1 - s2)^-1 mod q
    x = None
    for k,v in message_table.items():
        if len(v) > 1:
            sm0 = v[0]
            sm1 = v[1]
            k = get_k(sm0.m, sm1.m, sm0.s, sm1.s, q)
            x = get_x_from_known_k(k, sm0.m, q, sm0.r, sm0.s)
            actual_hash = hashlib.sha1(hex(x)[2:-1].encode()).hexdigest()
            if actual_hash != expected_hash:
                print "expected_hash %s" % (expected_hash)
                print "actual_hash   %s" % (actual_hash)
                exit(0)
            print " \"%s\" and \"%s\" have been signed with same key k : %d" % (sm0.msg, sm1.msg, k)
            
    
    print "private key   %d" % (x)
    print "expected hash %s" % (expected_hash)
    print "actual hash   %s" % (actual_hash)