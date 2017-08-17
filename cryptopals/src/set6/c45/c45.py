import sys
from dsa_helper import DSA


if __name__ == "__main__":
    p = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1
    q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
    g = 0
    m0 = "Hello, World"
    m1 = "Goodbye, World"
    dsa = DSA(p,q,g)

    print "---------- g = 0 ----------"
    r0, s0 = dsa.get_signature(m0)
    # validate original signature when g = 0
    if dsa.is_signature_valid(m0, r0, s0):
        print "message %s has valid signature %s,%s" % (m0, r0, s0)
    
    # validate signature of m0 against m1 for g = 0
    # this happens because when g = 0, then y = g ** x mod p = 0 and r = g ** k mod p mod q = 0
    # therefore the signature generated is always 0 irrespective of the message
    r1, s1 = dsa.get_signature(m1)
    if dsa.is_signature_valid(m1, r0, s0):
        print "message %s has valid FORGED signature %s,%s" % (m1, r0, s0)
    

    # trying g = 1
    print "---------- g = 1 ----------"
    g = 1
    dsa = DSA(p, q, g)
    r0, s0 = dsa.get_signature(m0)
    if dsa.is_signature_valid(m0, r0, s0):
        print "message %s has valid signature %s,%s" % (m0, r0, s0)

    r1, s1 = dsa.get_signature(m1)
    # In this case when g = 1, y and r are set to 1. Therefore the signature is 1 irrespective of the message
    if dsa.is_signature_valid(m1, r0, s0):
        print "message %s has valid FORGED signature %s,%s" % (m1, r0, s0)
 
    # g = p + 1 
    print "---------- g = p + 1 ----------"
    g = p + 1
    dsa = DSA(p, q, g)
    r0, s0 = dsa.get_signature(m0)
    if dsa.is_signature_valid(m0, r0, s0):
        print "message %s has valid signature %s,%s" % (m0, r0, s0)

    r1, s1 = dsa.get_signature(m1)
    # In this case when g = 1, y and r are set to 1. Therefore the signature is 1 irrespective of the message
    if dsa.is_signature_valid(m1, r0, s0):
        print "message %s has valid FORGED signature %s,%s" % (m1, r0, s1)
    print "y = %d" % (dsa.y)
