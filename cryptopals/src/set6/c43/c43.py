import sys
from dsa_helper import DSA
import hashlib
from crypto_math import CryptoMath



def get_x_from_known_k(k, h, q, r, s):
    
    # x = s * k - H(msg) mod q
    #     --------------
    #           r
    r_inv = CryptoMath.mod_inv(r, q)
    x = CryptoMath.mod_mul(s, k, q) - h
    x = CryptoMath.mod_mul(x, r_inv, q)
    return x

def get_key_from_nonce(kmin, kmax, msg, q, r, s, expected_privkey_hash):
    """ brute force all possible values for k and compute a key that validates the given signature"""
    msg_hash = hashlib.sha1(msg).hexdigest()
    h = int(msg_hash, 16)
    for k in range(kmin, kmax + 1):
        x = get_x_from_known_k(k, h, q, r, s)
        
        actual_hash = hashlib.sha1(hex(x)[2:-1].encode()).hexdigest()
        if actual_hash == expected_privkey_hash:
            return (x, k)

    return (None, None)


if __name__ == "__main__":
    p = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1
    q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
    g = 0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291
    y = int("84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4"
            "abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004"
            "e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed"
            "1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07b"
            "bb283e6633451e535c45513b2d33c99ea17", 16)
    expected_privkey_hash = "0954edd5e0afe5542a4adf012611a91912a3ec16"
    expected_sha1_int = 0xd2d0714f014a9784047eaeccf956520045c45265
    
    dsa = DSA(p, q, g)
    
    # ensure that message is in the expected format
    msg = """For those that envy a MC it can be hazardous to your health\nSo be friendly, a matter of life and death, just like a etch-a-sketch\n"""
    actual_sha1 = hashlib.sha1(msg).hexdigest()
    actual_sha1_int = int(actual_sha1, 16)
    assert(actual_sha1_int == expected_sha1_int)
    
    r,s = dsa.get_signature(msg)
    assert(dsa.is_signature_valid(msg, r, s) == True)

    # compute private key from given signature
    r = 548099063082341131477253921760299949438196259240
    s = 857042759984254168557880549501802188789837994940
    x, k = get_key_from_nonce(0, 1 << 16, msg, q, r, s, expected_privkey_hash)
    if x is not None:
        print "found private key %d with hash %s; k =  %d" % (x, hashlib.sha1(hex(x)[2:-1].encode()).hexdigest(), k)
    else:
        print "Failed to compute private key"
