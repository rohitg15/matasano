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


if __name__ == "__main__":
    seed = int(time.time())
    print "seed:", seed
    mt = MT19937(seed)
    for i in range(10):
        print mt.extract_number()

