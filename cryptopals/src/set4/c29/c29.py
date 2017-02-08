import sys
import struct
import hashlib
from Crypto import Random


# represents the custom SHA1 implementation
class Sha1:
    """ Class that implements hashlib's SHA1 Algorithm '"""
    def __init__(self, init_state = []):
        self.state = []
        if len(init_state) == 5:
            for i in range(len(init_state)):
                self.state.append(init_state[i])
        else:
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

    # message length is taken as a parameter because when a custom hash is computed after length extension, 
    # the length inserted in the end must be the length of the entire payload and not just the exploit
    def get_hex_digest(self, message, msg_len = 0):

        # stage 1: message (including the padding must be a multiple of 64 bytes)
        #          Last 8 bytes must represent the original length of the message in Big Endian
        #          The bytes between the message and the begining of the last 8 bytes must be filled with a 
        #          1 (in Big Endian) followed by 0s until the overall length of the padded message is a multiple
        #          of 64 bytes
       # message = "A"*16 + message
        mbytes = bytearray(message)
        ml = len(mbytes)
        if msg_len == 0:
            msg_len = ml
        padding = chr(128) + chr(0) * (55 - len(mbytes) % 64)
        if len(mbytes) % 64 > 55:
            padding += chr(0) * (64 + 55 - len(mbytes) % 64) 
        
        # add a 1 followed by as many zeroes as it takes to create an overall message that is just 64 bytes short
        # of the nearest multiple of self.base_len (64 bytes)
        
        # add the length of the padded message with zeroes prepended; the length must be stored in bits
        padded_mbytes = mbytes + bytearray(padding) + bytearray(struct.pack('>Q', 8 * msg_len))
       
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


# Represents the server program that we are attacking
class Server:

    def __init__(self):
        self.key = Random.get_random_bytes(16)

    def get_mac(self, message):
        return hashlib.sha1(self.key + message).digest()

    def get_mac_hex(self, message):
        return hashlib.sha1(self.key + message).hexdigest()

    def validate(self, message, hex_digest):
        if hex_digest == self.get_mac_hex(message):
            return "admin=true" in message
        return False


def get_padded_message(message):
    mbytes = bytearray(message)
    # 1 byte for the 0x128 and 8 bytes for the length of the message
    offset = 64 - (len(mbytes) % 64)
    num_zeroes = 0
    if offset < 9:
        num_zeroes = 64 - 9 + offset
    else:
        num_zeroes = offset - 9
    # padding : 1 at the begining, length of the message in bits (stored in a byte) at the end, with as many zeroes in between as it takes to make the
    #           entire construction a multiple of 64 bytes
    padding = chr(128) + chr(0)*num_zeroes + struct.pack('>Q', 8*len(mbytes))
    return mbytes + bytearray(padding)

if __name__ == "__main__":
    message = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    m = Server()
    message_digest = m.get_mac(message)

    # unpack hash into 5 words
    words = struct.unpack(">IIIII", message_digest)
    state = [word for word in words]
    exploit = ";admin=true"

    # brute force key length    
    for key_len in range(1024):
        # ignore the first 16 bytes as the server would prepend the key. The padding is more important here
        exploit_prefix = get_padded_message(key_len*"A" + message)[key_len:]
        payload = exploit_prefix + exploit
        
        # the forged message must include the length of the original message(bytes) at the end of its payload
        h = Sha1(state)
        payload_mac = h.get_hex_digest(exploit, len(payload) + key_len)
        if m.validate(payload, payload_mac):
            print "key length : " + str(key_len)
            print "forged digest : " + payload_mac
            print "logged in as admin!"
            break
        

    