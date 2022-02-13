from hashlib import sha256
import Crypto
from crypto_math import CryptoMath, Point, EllipticCurve
from Crypto import Random
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Hash import HMAC, SHA256
import math
import random


# 59. Elliptic Curve Diffie-Hellman and Invalid-Curve Attacks

class User:
    def __init__(self, ec :EllipticCurve, base_point :Point, base_order :int, num_bits :int = 128):

        self.ec = ec
        self.base_point = base_point
        self.key_size_bits = num_bits
        key_size_bytes = self.key_size_bits >> 3

        while True:
            candidate = bytes_to_long( Random.get_random_bytes( key_size_bytes ) )
            if candidate >= 2 and candidate < base_order:
                self.ec_private_key = candidate
                break
        
        print ("private key {0}".format( self.ec_private_key ))
        self.ec_public_key = self.ec.scale( self.base_point, self.ec_private_key )

    def get_public_key(self) -> Point:
        return self.ec_public_key
    
    def get_shared_key(self, other_public_key :Point) -> Point:
        sk = self.ec.scale( other_public_key, self.ec_private_key )
        return sk
    
    def get_shared_key_bytes(self, other_public_key :Point) -> bytes:
        return long_to_bytes( self.get_shared_key(other_public_key).x )
    

    def send_message(self, msg, other_public_key):
        key = self.get_shared_key_bytes(other_public_key)

        h = HMAC.new(key, digestmod=SHA256)
        h.update(str.encode(msg))

        return ( self.get_public_key(), msg, h.hexdigest() )
    
    def receive_valid_message(self, msg, hexdigest, other_public_key):
        key = self.get_shared_key_bytes(other_public_key)

        h = HMAC.new(key, digestmod=SHA256)
        h.update(str.encode(msg))

        try:
            h.hexverify(hexdigest)
        except:
            return False
        
        return True


def find_factors(n :int) -> int:
    print (CryptoMath.lenstra_ecm_factorization(n))


if __name__ == "__main__":
    G = Point(182, 85518893674295321206118380980485522083)

    base_order = 29246302889428143187362802287225875743
    curve_order = 233970423115425145498902418297807005944

    ec = EllipticCurve(-95051, 11279326, 233970423115425145524320034830162017933, curve_order)
    


    alice = User(ec, G, base_order)
    bob = User(ec, G, base_order)

    message = "hello ecc world!"
    alice_public_key, msg, digest = alice.send_message(message, bob.get_public_key())

    assert( True == bob.receive_valid_message(message, digest, alice.get_public_key()) )

    # y^2 = x^3 - 95051*x + 210
    # y^2 = x^3 - 95051*x + 504
    # y^2 = x^3 - 95051*x + 727

    # 233970423115425145550826547352470124412
    # 233970423115425145544350131142039591210
    # 233970423115425145545378039958152057148

    # NOTE: ensure invalid curve groups are all cyclic, otherwise no guarantee that subgroup of order dividing group order exists

    invalid_curves = [
                        EllipticCurve(-95051, 210, 233970423115425145524320034830162017933, 116985211557712572775413273676235062206), 
                        EllipticCurve(-95051, 504, 233970423115425145524320034830162017933, 233970423115425145544350131142039591210),
                        EllipticCurve(-95051, 727, 233970423115425145524320034830162017933, 233970423115425145545378039958152057148),

                        # Genrated using the following sage script
                        # a = -95051
                        # b = 100
                        # q = 233970423115425145524320034830162017933
                        # Fq = GF(q)
                        # ec = EllipticCurve(Fq, [a, b])
                        # G = ec.gen(0) -- base point
                        # G.order()
                        # ec.order()
                        # factor(ec.order())
                        # P = Integer(G.order() / factor) * G
                        # P.order() == factor
                        EllipticCurve(-95051, 100, 233970423115425145524320034830162017933, 233970423115425145534154737197162143155),
                        EllipticCurve(-95051, 222, 233970423115425145524320034830162017933, 233970423115425145511640817248424186178),
                        EllipticCurve(-95051, 13, 233970423115425145524320034830162017933, 233970423115425145528350255370787428509),
                        EllipticCurve(-95051, 173, 233970423115425145524320034830162017933, 233970423115425145524165113833558156540),
                        EllipticCurve(-95051, 155, 233970423115425145524320034830162017933, 233970423115425145548478987245836852496),
                        EllipticCurve(-95051, 385, 233970423115425145524320034830162017933, 233970423115425145503548383368487338110),
                        EllipticCurve(-95051, 208, 233970423115425145524320034830162017933, 233970423115425145524457691320840735922)
                    ]
    
    invalid_curve_orders = [116985211557712572775413273676235062206, 233970423115425145544350131142039591210, 233970423115425145545378039958152057148]

    # obtain factors of the invalid orders 
    # include enough factors to ensure product > base_order * base_order
    # esnure each factor is distinct
    invalid_curve_factors = [
        [2, 3, 11, 23, 31, 89, 4999, 28411, 45361],
        [5, 7, 61, 12157, 34693],
        [37, 67, 607, 1979, 13327, 13799],
        [10091],
        [30829],
        [1279],
        [58991],
        [2287],
        [5563],
        [43, 719, 1237]
    ]

    assert( len(invalid_curves) == len(invalid_curve_factors) )

    
    # check we have enough primes such that product >= square of base_order
    # since only x-coordinate is used to derive shared key for HMAC, 
    # we don't know if we've identified (x, y) or (x, -y).
    # which corresponds to si = s mod pi or -si = s mod pi 
    # however, si^2 = s^2 mod pi
    # so we square the recovered key shares and find square root in the end

    res = math.prod( [ math.prod(x) for x in invalid_curve_factors ] )
    assert( res >= base_order * base_order )

    # recover ECC private key
    private_key_shares = []
    moduli = []
    for i in range( len(invalid_curve_factors) ):
        for invalid_curve_factor in invalid_curve_factors[i]:
            print ("finding curve points for factor {0}".format( invalid_curve_factor ))

            # find point on invalid_curve[i] that generates subgroup of order invalid_curve_factor
            invalid_pub_key = invalid_curves[i].get_point_with_order( invalid_curve_factor )

            print ("----- found invalid curve public key point {0}, {1}".format( invalid_pub_key.x, invalid_pub_key.y ) )
            
            _, _, xdigest = alice.send_message(message, invalid_pub_key)

            # brute force possible values 
            key_share = None
            for k in range(invalid_curve_factor):
                key = long_to_bytes( ec.scale(invalid_pub_key, k).x )
                hmac = HMAC.new(key, digestmod=SHA256)
                hmac.update(str.encode(message))
                try:
                    hmac.hexverify(xdigest)

                    # we pick k*k as described above 
                    key_share = k*k
                    break
                except:
                    continue
            
            assert(key_share is not None)

            print ("----- found key share {0} for modulus {1}".format( key_share, invalid_curve_factor ))
            private_key_shares.append( key_share )
            moduli.append( invalid_curve_factor )
    

    # verify all moduli are prime
    for modulus in moduli:
        assert(CryptoMath.miller_rabin_is_prime(modulus) == True)
    
    print ("verified all moduli are prime")

    alice_private_key_sq = CryptoMath.crt(private_key_shares, moduli)
    alice_private_key = CryptoMath.get_nth_root(alice_private_key_sq, 2)

    print ("alice's private key computed by mallory = {0}".format( alice_private_key ))
    
    computed_pub_key = ec.scale(G, alice_private_key)
    print ("computed alice public key {0}, {1}".format( computed_pub_key.x , computed_pub_key.y))
    print ("original alice public key {0}, {1}".format( alice_public_key.x, alice_public_key.y ))
    assert(alice_public_key == computed_pub_key)




    


    
    
    


