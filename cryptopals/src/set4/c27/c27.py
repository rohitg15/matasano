import sys
import os
script_path = "../../"
sys.path.append(os.path.abspath(script_path))
import base
from Crypto import Random
from Crypto.Cipher import AES

key = iv = Random.get_random_bytes(16)

def find_key(pt0, pt1, pt2) :
    plaintext = pt0 + pt1 + pt2

class Oracle:
    def __init__(self):
        """ Define key, iv for AES CBC cipher """
        self.key = Random.get_random_bytes(16)
        self.iv = self.key
    def encrypt(self, plaintext):
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        return cipher.encrypt(plaintext)
    def decrypt(self, ciphertext):
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        return cipher.decrypt(ciphertext)
    def get_key(self):
        return self.key

if __name__ == "__main__":
    # use the oracle to encrypt plaintext
    o = Oracle()
    plaintext = "A" * 48
    ciphertext = o.encrypt(plaintext)
    block_size = 16
    cipher_bytes = bytearray(ciphertext)

    # split ciphertext into blocks and rearrange them in such a way that the second block is zeroed and the first, third blocks are the same
    # in that case the first and third blocks of the plaintext that we get can be XORed to get the key
    modified_blocks = bytearray()
    zero_block = bytearray()
    for i in range(block_size):
        zero_block.append(0)
    
    # modify ciphertext to force the key to be returned as part of the plaintext
    modified_blocks = modified_blocks + cipher_bytes[0:16]
    modified_blocks = modified_blocks + zero_block
    modified_blocks = modified_blocks + cipher_bytes[0:16]
    modified_cipher = ''.join([chr(byte) for byte in modified_blocks])

    # decrypt modified ciphertext using the Oracle
    cipher_key = o.decrypt(modified_cipher)

    # derive key by XORing the first and last plaintext blocks
    derived_key = base.equal_size_xor(bytearray(cipher_key[0:block_size]), bytearray(cipher_key[32:48]))
    kb = [ord(k) for k in o.get_key()]
    if derived_key == kb:
        print "cracked the key"
    else:
        print "failed to obtain key"
        