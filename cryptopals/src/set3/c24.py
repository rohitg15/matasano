import sys
from Crypto import Random
import random
import time

class MT19937:
    """ custom python implementation of the mersenne twister 19937 algorithm for pseudo-random number generation"""

    def __init__(self, seed):
        """ initialize the internal state of the MT19937 algorithm"""
        # MT 19937 constants
        self.state_size = 624
        self.mt_const0 = 1812433253
        self.mt_const1 = 2636928640
        self.mt_const2 = 4022730752
        self.mt_const3 = 0x80000000
        self.mt_const4 = 0x7fffffff

        # use this to maintain state for getting a single byte every time
        self.num = None
        self.count = 0
        
        self.index = 0
        self.mt = [0] * self.state_size
        self.mt[0] = seed
        for i in range(1, self.state_size):
            self.mt[i] = self.get_lsb(self.mt_const0 * (self.mt[i - 1] ^ self.mt[i - 1] >> 30) + i, 32)
    
    def set_state(self, new_state):
        """ method to set the state directly"""
        if self.state_size != len(new_state):
            raise()
        
        self.index = 0
        self.mt = [0] * self.state_size
        
        for i in range(self.state_size):
            self.mt[i] = new_state[i]


    def get_byte(self):
        """extract one random byte at a time"""
        if self.num == None:
            # since extract_number gives 4 bytes, we return one byte at a time and update a count
            # the count is used to return the appropriate byte 
            self.num = self.extract_number()
            self.count = 4
        mask = 1 << (self.count-1)
        byte = self.num & (mask)
        self.count = self.count - 1
        if self.count == 0:
            self.num = None
        return byte

    def extract_number(self):
        if self.index >= self.state_size:
            self.twist()
        
        y = self.mt[self.index]
        y = y ^ y >> 11
        y = y ^ y << 7 & self.mt_const1
        y = y ^ y << 15 & self.mt_const2
        y = y ^ y >> 18
        self.index = self.index + 1
        return self.get_lsb(y, 32)
    
    def twist(self):
        for i in range(self.state_size):
            y = self.get_lsb(((self.mt[i]) & self.mt_const3) + (self.mt[(i + 1) % self.state_size] & self.mt_const4))
            self.mt[i] = self.mt[(i + 397) % self.state_size] ^ y >> 1
            if y % 2 != 0:
                self.mt[i] = self.mt[i] ^ 0x9908b0df
        self.index = 0

    def get_lsb(self, x, w=32):
        """ get the 2 least significant bits of x"""
        mask = (1 << w) - 1
        return int(x & mask)


class MT19937Cipher:
    def __init__(self, seed):
        """ we take only 16 bits of the seed"""
        self.mt = MT19937(seed & 0xFFFF)
        self.keystream = []

    def encrypt(self, plaintext):
        cipher_bytes = []
        for byte in plaintext:
            key_byte = self.mt.get_byte()
            self.keystream.append(key_byte)
            cipher_bytes.append( chr((key_byte ^ ord(byte)) & 0xFF) )
        return ''.join([char for char in cipher_bytes])
    
    def decrypt(self, ciphertext):
        # do a sanity check
        if len(self.keystream) != len(ciphertext):
            raise()
        plaintext_bytes = []
        for cipher_char, key_char in zip(ciphertext, self.keystream):
            plaintext_bytes.append( chr((ord(cipher_char) ^ key_char) & 0xFF) )
        return ''.join([char for char in plaintext_bytes])


def verify_MT19937Cipher():
    """Test the stream cipher"""
    plaintext = "h#llo PRNG stream cipher w@rld!!!!"
    cipher = MT19937Cipher(0xdeadbeef)
    ciphertext = cipher.encrypt(plaintext)
    decrypted_plaintext = cipher.decrypt(ciphertext)
    is_match = plaintext.__eq__(decrypted_plaintext)
    assert(is_match == True)
        

def encryption_oracle(known_plaintext, seed = None):
    """ generates a random token from a known plaintext and a randomly generated prefix """
    # generate the random prefix
    prefix_len = random.randint(4, 20)
    prefix = Random.get_random_bytes(prefix_len)

    # generate a random 16 bit seed
    if seed is None:
        rand_seed = random.randint(0, 2**16-1)
    else:
        rand_seed = seed
    cipher = MT19937Cipher(rand_seed)
    ciphertext = cipher.encrypt(prefix + known_plaintext)
    return (rand_seed, ciphertext)

def compute_seed_from_known_pt(known_plaintext, ciphertext):
    """given a known plaintext suffix and a ciphertext, compute the 16 bit value used to seed the MT19937 
       stream cipher that was in turn used to generate the ciphertext """
    prefix_len = len(ciphertext) - len(known_plaintext)
    ciphertext_suffix = ciphertext[prefix_len:]

    known_keystream = [c ^ p for c,p in zip(bytearray(ciphertext_suffix), bytearray(known_plaintext))]
    matches = []
    # brute force the random_seed
    for seed in range(2**16):
        mt = MT19937(seed)
        # ignore the first prefix_len bytes
        for times in range(prefix_len):
            mt.get_byte()
        
        # match the next len(known_plaintext) bytes with the known keystream
        is_match = True
        for key_byte in known_keystream:
            if key_byte != mt.get_byte():
                is_match = False
                break
        if is_match:
            matches.append(seed)
    return matches

def get_password_reset_token(known_plaintext, current_time):
    """generates a password reset token (in hex) using MT19937Cipher seeded with the current time """
    return encryption_oracle(known_plaintext, current_time)[1].encode('hex')

def is_token_for_current_time(token, known_plaintext, current_time):
    """ Given a password reset token and a known suffix of the plaintext, it returns whether or not
        the current time is being used as a seed"""
    expected_seed_times = compute_seed_from_known_pt(known_plaintext, token)
    for expected_time in expected_seed_times:
        if expected_time == (current_time & 0xFFFF):
            return True
    return False


if __name__ == "__main__":
    # verify the MT19937 algorithm
    verify_MT19937Cipher()

    # encrypt prefix + known_plaintext
    known_plaintext = "A"*14
    original_seed, ciphertext = encryption_oracle(known_plaintext)
    
    # compute a password reset token
    current_time = int(time.time())
    reset_token_hex = get_password_reset_token(known_plaintext, current_time)
    print "known plaintext suffix      : ", known_plaintext
    print "password reset token in hex : ", reset_token_hex
    print "is token for current time   : ", is_token_for_current_time(reset_token_hex.decode('hex'), known_plaintext, current_time)
    
            

    