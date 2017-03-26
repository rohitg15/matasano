import sys
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
        
        self.index = 624
        self.mt = [0] * self.state_size
        self.mt[0] = seed
        for i in range(1, self.state_size):
            self.mt[i] = self.get_lsb(self.mt_const0 * (self.mt[i - 1] ^ self.mt[i - 1] >> 30) + i, 32)

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


def get_random_number():
    """ Waits for a random number of seconds between 40 and 1000; 
        seeds the MT19937 with the current time; waits again and returns the first 32 bit random number"""
    rand_num0 = random.randrange(40, 1000)
    rand_num1 = random.randrange(40, 1000)
    
    print "waiting for %s seconds" % (str(rand_num0))
    time.sleep(rand_num0)
    seed = int(time.time())
    print "original seed: %s" % (str(seed))
    mt = MT19937(seed)
    print "waiting for %s seconds" % (str(rand_num1))
    time.sleep(rand_num1)
    return mt.extract_number()

if __name__ == "__main__":
    rand_num = get_random_number()
    current_ts = int(time.time())
    print "got number %s, cracking seed..." % (str(rand_num))
    for ts in range(current_ts - 1500, current_ts):
        mt = MT19937(ts)
        guess_rand_num = mt.extract_number()
        if guess_rand_num == rand_num:
            print "found seed %s" % (str(ts))
            exit(0)
    print "could not find seed, try a larger time range"
    
