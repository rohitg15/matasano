import sys
import os
import struct
import hashlib

class Sha1:
    """ Class that implements hashlib's SHA1 Algorithm '"""
    def __init__(self):
        self.state = [
            0x67452301,
            0xEFCDAB89,
            0x98BADCFE,
            0x10325476,
            0xC3D2E1F0
        ]
        # length in bytes
        self.base_len = 64
        self.pad_len = 8

    def left_rot(self, n, x, w = 32):
        # since python integers are not 4 bytes, result might get cast into a long. Hence the mask
        return ((n << x) | (n >> (w - x))) & 0xFFFFFFFF
    
    # input : 2 words
    # output : xor of the 2 words
    def xor_words(self, word1, word2):
          return (word1 ^ word2) & 0xFFFFFFFF 

    def get_hex_digest(self, message):

        # stage 1: message (including the padding must be a multiple of 64 bytes)
        #          Last 8 bytes must represent the original length of the message in Big Endian
        #          The bytes between the message and the begining of the last 8 bytes must be filled with a 
        #          1 (in Big Endian) followed by 0s until the overall length of the padded message is a multiple
        #          of 64 bytes

        mbytes = bytearray(message)
        ml = len(mbytes)
        padding = chr(128) + chr(0) * (55 - len(mbytes) % 64)
        if len(mbytes) % 64 > 55:
            padding += chr(0) * (64 + 55 - len(mbytes) % 64) 
        
        # add a 1 followed by as many zeroes as it takes to create an overall message that is just 64 bytes short
        # of the nearest multiple of self.base_len (64 bytes)
        
        # add the length of the padded message with zeroes prepended; the length must be stored in bits
        padded_mbytes = mbytes + bytearray(padding) + bytearray(struct.pack('>Q', 8 * len(mbytes)))
       
        # stage 2: divide the padded message into 64 byte chunks
        #chunks = [padded_mbytes[i * self.base_len : (i + 1) * self.base_len] for i in range(len(padded_mbytes) / self.base_len)]
        chunks = [padded_mbytes[i:i+64] for i in range(0, len(padded_mbytes), 64)]

        for chunk in chunks:
            # break chunk into 16 four byte Big Endian words
            wsize = 4
            w = [chunk[i * wsize : (i + 1) * wsize] for i in range(len(chunk) / wsize)]
            
            # each w[i] is a bytearray. Convert it t a single word
            for i in range(16):
                w[i] = ((w[i][0] << 24) | (w[i][1] << 16) | (w[i][2] << 8) | w[i][3])
            
            # extend the 16 words to 80 words
            for i in range(16, 80):
                temp0 = self.xor_words(w[i-3], w[i-8])
                temp1 = self.xor_words(temp0, w[i-14])
                temp2 = self.xor_words(temp1, w[i-16])
                w.append(self.left_rot(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1))
            
            # initialize the hash values for this chunk
            a = self.state[0]
            b = self.state[1]
            c = self.state[2]
            d = self.state[3]
            e = self.state[4]

            for i in range(80):
                if i >= 0 and i <=19:
                    f = ((b & c) | ((~ b) & d)) & 0xFFFFFFFF
                    k = 0x5A827999
                elif i >= 20 and i <= 39:
                    f = (b ^ c ^ d) & 0xFFFFFFFF
                    k = 0x6ED9EBA1
                elif i >= 40 and i <= 59:
                    f = ((b & c) | (b & d) | (c & d)) & 0xFFFFFFFF
                    k = 0x8F1BBCDC
                elif i >= 60 and i<= 79:
                    f = (b ^ c ^ d) & 0xFFFFFFFF
                    k = 0xCA62C1D6
                
                temp = ((self.left_rot(a, 5) + f + e + k + w[i]) & 0xFFFFFFFF)
                e = d
                d = c
                c = self.left_rot(b, 30)
                b = a
                a = temp

            # add this chunk's hash to the result so far
            self.state[0] = (self.state[0] + a) & 0xFFFFFFFF
            self.state[1] = self.state[1] + b & 0xFFFFFFFF
            self.state[2] = self.state[2] + c & 0xFFFFFFFF
            self.state[3] = self.state[3] + d & 0xFFFFFFFF
            self.state[4] = self.state[4] + e & 0xFFFFFFFF

        return '%08x%08x%08x%08x%08x' % (self.state[0], self.state[1], self.state[2], self.state[3], self.state[4])
        
    
if __name__ == "__main__":
    hash = Sha1()
    
    # test message with a bitstring
    message = "hello world!"
    print "message  : " + message
    print "expected : " + hashlib.sha1(message).hexdigest()
    print "got      : "  + hash.get_hex_digest(message)
    