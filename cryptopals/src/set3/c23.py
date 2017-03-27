import sys
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


class ReverseMT19937:

    def get_msb(self, x, n, w = 32):
        if n < 0:
            return 0
        return (x >> (w - n - 1)) & 1

    def set_msb(self, x, n, v, w = 32):
        return x | (v << (w - n - 1))

    def get_lsb(self, x, n, w = 32):
        if n < 0:
            return 0
        return (x >> n) & 1
    

    def set_lsb(self, x, n, v, w = 32):
        return x | (v << n)

    def untemper_rshift_xor(self, y, s, w = 32):
        """ reverse the right shift and xor. Idea here is that the s bits in y from the left, will be preserved
            because of the right shift. Thus they can be mapped directly back to the original input. The next
            s bits can be obtained by XORing the respective bits in y and the corresponding bit in the first s bits
            from the left """
        x = 0
        for i in range(w):
            # get_msb(x, i - s) corresponds to the corresponding bit before the right shift, that was XORed in the 
            # first place
            x = self.set_msb(x, i, self.get_msb(y, i) ^ self.get_msb(x, i - s))
        return x
    

    def untemper_lshift_xor_and(self, y, s, m, w = 32):
        """ reverse the left shift, xor and logical and with a mask. Idea here is similar to the previous case 
            except we need to consider operations in lsb instead of msb, and there is a logical AND with a mask
            that must be done. The s bits from lsb are preserved and hence mapped directly to input. The next 
            s bits are obtained by an XOR with the corresponding bit in the first s bits from lsb after performing
            a logical AND with the corresponding bit in the mask in order to decide whether or not that bit gets
            preserved"""
        x = 0
        for i in range(w):
            # get_lsb(m, i) is the masking bit at position i. This corresponds to y's position (i) and not
            # the position i-s
            x = self.set_lsb(x, i, self.get_lsb(y, i) ^ ( self.get_lsb(x, i - s) & self.get_lsb(m, i) ))
        return x

    def untemper(self, num):
        """ reverse the tempering logic in MT19937's extract_number function"""
        y = num
        y = self.untemper_rshift_xor(y, 18)
        y = self.untemper_lshift_xor_and(y, 15, 0xefc60000)
        y = self.untemper_lshift_xor_and(y, 7, 0x9d2c5680)
        y = self.untemper_rshift_xor(y, 11)
        return y
        

    def get_MT19937_state(self, numbers):
        """ for every number in the input, reverse the tempering logic and re-create the original state"""
        state = []
        for num in numbers:
            state.append(self.untemper(num))
        return state

if __name__ == "__main__":
    # seed with current timestamp and get first 624 numbers
    seed = int(time.time())
    mt = MT19937(seed)
    numbers = []
    for times in range(624):
        numbers.append(mt.extract_number())
    
    # get the internal state of the MT19937 algorithm from the given numbers
    rmt = ReverseMT19937()
    state = rmt.get_MT19937_state(numbers)
    
    # initialize the MT19937's custom implementation with the generated state vector and generate 624 random numbers
    mt.set_state(state)
    generated_nums = []
    for i in range(624):
        generated_nums.append(mt.extract_number())
    
    # validate the generated numbers and original numbers
    isBroken = True
    for x,y in zip(numbers, generated_nums):
        if x!=y:
            print "%s and %s" % (str(x) , str(y))
            isBroken = False
    if isBroken:
        print "generated entire random sequence successfully"

    
    