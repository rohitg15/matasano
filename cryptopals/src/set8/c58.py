from crypto_math import CryptoMath
from Crypto import Random
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Hash import HMAC, SHA256
import random

p = 11470374874925275658116663507232161402086650258453896274534991676898999262641581519101074740642369848233294239851519212341844337347119899874391456329785623
g = 622952335333961296978159266084741085889881358738459939978290179936063635566740258555167783009058567397963466103140082647486611657350811560630587013183357
q = 335062023296420808191071248367701059461

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
        
        print ( "original private key = {0}".format( self.dh_private_key ) )
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

        print ("hexdigest inside receive = {0}".format( h.hexdigest() ))

        try:
            h.hexverify(hexdigest)
        except:
            return False
        
        return True

    def get_private_exponent(self):
        return self.dh_private_key


if __name__ == "__main__":
    alice = User()
    bob = User()
    msg = "hello world"
    bob_public_key, msg, hexdigest = bob.send_message(msg, alice.get_public_key())




    assert( alice.receive_valid_message(msg, hexdigest, bob_public_key) == True )

    # j = (p - 1) // q : 34233586850807404623475048381328686211071196701374230492615844865929237417097514638999377942356150481334217896204702
    # 76404216680248147890725465466734243970853371218438495046025185507551527833728478710665337 is also a factor of j
    factors = [2, 12457, 14741, 18061, 31193, 33941, 63803]
    partial = []

    mallory = User()

    r = 1
    for f in factors:
        r = r * f

        # step 1: compute generator of a small subgroup
        h = 1
        while True:
            h = random.randint(1, p - 1)
            h = pow(h, ( p - 1) // f, p)
            if h != 1:
                break

        assert(h != 1)
        print ( "found generator {0}".format( h ) )
        

        # step 2: send generator as public key to bob
        h_pub_key = long_to_bytes(h)
        _, _, hexdigest = bob.send_message(msg, h_pub_key)

        # step 3: compute partial secret bits
        for i in range(f):
            ss = pow( h, i, p )
            key = long_to_bytes( ss )
            hmac = HMAC.new( key, digestmod=SHA256 )
            hmac.update( str.encode(msg) )
            if hexdigest == hmac.hexdigest():
                print ("Found partial key {0} for factor {1}".format( i, f ))
                partial.append(i)
                break
        
    assert( len(partial) == len(factors) )

    # step 4: recover partial private exponent using CRT
    # this would give x mod r where r = f1 * f2 ... fk
    t = CryptoMath.crt(partial, factors)

    print ( "computed partial private key = {0}".format( t ))

    # step 5: recover remaining bits of bob's private exponent using pollards kangaroo algorithm
    # prv = tm + r
    # y = g ** prv = (g ** tm) * (g ** r)
    # y * (g ** -r) = (g ** tm)
    # g' = g ** t
    # y' = y * (g ** -r)
    
    y = bytes_to_long( bob_public_key )
    yt = pow(g, p - 2, p)
    yt = ( y * pow(yt, r, p) ) % p

    gt = pow(g, t, p)

    # solve for m using pollard's kangaroo algorithm
    # m = O( (p - 1) // r )
    print ("computing remaining bits using pollard's kangaroo algorithm")
    m = CryptoMath.pollards_kangaroo_dlog(yt, gt, p, 1, (p - 1) // r)
    prv = m*t + r

    print ( "recovered private key = {0}".format( prv ))
    pub_key = pow(g, m, p)
    assert(bob_public_key == long_to_bytes(pub_key))










