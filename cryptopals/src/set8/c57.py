from crypto_math import CryptoMath
from Crypto import Random
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Hash import HMAC, SHA256
import random

#  57. Diffie-Hellman Revisited: Small Subgroup Confinement
p = 7199773997391911030609999317773941274322764333428698921736339643928346453700085358802973900485592910475480089726140708102474957429903531369589969318716771
g = 4565356397095740655436854503483826832136106141639563487732438195343690437606117828318042418238184896212352329118608100083187535033402010599512641674644143
q = 236234353446506858198510045061214171961

class User:
    # q.bit_length() = 128 
    def __init__(self, num_bits = 128):
        self.key_size_bits = num_bits
        key_size_bytes = self.key_size_bits // 8

        # NOTE: this is done so that the value is < q (order of the generator g)
        while True:
            self.dh_private_key = bytes_to_long(Random.get_random_bytes(key_size_bytes))
            if self.dh_private_key > 0  and self.dh_private_key < q:
                break
        
        self.dh_public_key = CryptoMath().mod_exp(g, self.dh_private_key, p)

    
    def get_public_key(self) -> bytes:
        return long_to_bytes(self.dh_public_key)
    
    def get_shared_key(self, other_public_key_bytes):
        other_public_key = bytes_to_long(other_public_key_bytes)
        ss = CryptoMath().mod_exp(other_public_key, self.dh_private_key, p)

        return long_to_bytes(ss)

    def send_message(self, msg, other_public_key_bytes):
        key = self.get_shared_key(other_public_key_bytes)

        h = HMAC.new(key, digestmod=SHA256)
        h.update(str.encode(msg))

        return ( self.get_public_key(), msg, h.hexdigest() )
    
    def receive_valid_message(self, msg, hexdigest, other_public_key_bytes):
        key = self.get_shared_key(other_public_key_bytes)

        h = HMAC.new(key, digestmod=SHA256)
        h.update(str.encode(msg))

        try:
            h.hexverify(hexdigest)
        except:
            return False
        
        return True

    def get_private_exponent(self):
        return self.dh_private_key


if __name__ == "__main__":
    # test basic diffie hellman key exchange
    alice = User()
    bob = User()

    msg = 'crazy flamboyant for the rap enjoyment'
    bob_public_key = bob.get_public_key()
    alice_public_key, msg, hexdigest = alice.send_message(msg, bob_public_key)

    assert (bob.receive_valid_message(msg, hexdigest, alice_public_key) == True)

    # mallory

    mallory = User()

    # factors of (p - 1) // q from factordb
    # we only need enough factors such that their product >= q to recover private key
    factors = [2, 5, 9, 109, 7963, 8539, 20641, 38833, 39341, 46337, 51977, 54319]

    partial = []

    for f in factors:
        # step 1: get generator of small subgroup
        h = 1
        while True:
            a = random.randint(2, p - 2)
            h = pow(a, (p - 1) // f, p)
            if h != 1:
                break

        assert(h != 1)
        # step 2: send public key (small subgroup generator) to bob
        mallory_public_key = long_to_bytes(h)

        # step 3: compute partial information about bob's private key
        _, msg, t = bob.send_message(msg, mallory_public_key)
        for i in range(f):
            # NOTE: h = bytes_to_long(mallory_public_key)
            ss = pow(h, i, p)
            key = long_to_bytes(ss)
            hmac = HMAC.new(key, digestmod=SHA256)
            hmac.update(str.encode(msg))
            if hmac.hexdigest() == t:
                print ("found partial : ", i)
                partial.append(i)
                break
        
    
    assert(len(partial) == len(factors))
    
    # step 4: recover bob's private exponent using CRT
    bob_private_exponent = CryptoMath.crt(partial, factors)
    bob_public_exponent = pow(g, bob_private_exponent, p)
    assert(bob_public_key == long_to_bytes(bob_public_exponent))


    print ("recovered private exp = ", bob_private_exponent)
    print ("bob's real private exponent = ", bob.get_private_exponent())



        
        





    




    


    


    
