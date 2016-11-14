import sys
from Crypto import Random
from Crypto.Cipher import AES
import base
import struct
import base64

key_base = Random.get_random_bytes(16)
nonce = 0x0

# read bytes from the file and encrypt using AES in CTR mode
def encrypt_file(filename, key, nonce):
    data = ""
    with open(filename, "r") as file:
        data = file.read()

    # encrypt plaintext
    return base.aes_ctr_manual_encrypt(data, key)

# decrypt the ciphertext using AES CTR 
def decrypt(ciphertext, key, nonce):
    return base.aes_ctr_manual_decrypt(ciphertext, key)

# for now assume offset is a multiple of block size
def edit(ciphertext, key, offset, newtext):
    block_size = 16
    cipherlen = len(ciphertext)
    newlen = len(newtext)
    newtext_bytes = bytearray(newtext)
    cipher_bytes = bytearray(ciphertext)
    output_bytes = bytearray()

    # identify the starting and ending blocks, divide up ciphertext bytes into blocks
    block_start = offset / block_size
    block_end = (offset + newlen) / block_size
    cipher_blocks = [ cipher_bytes[i * block_size : (i + 1) * block_size] for i in range (len(cipher_bytes) / block_size)]
    newtext_blocks = [ newtext_bytes[i * block_size : (i + 1) * block_size] for i in range (len(newtext_bytes) / block_size)]

    # move the counter and nonce for the prefix (which is from the ciphertext and not newtext)
    ctr = 0x0
    nonce = 0x0
    for block in range(block_start):
        ctr = ctr + 1
        if (ctr == 0x0):
            nonce = nonce + 1

    # assuming offset is aligned to block size
    num_blocks = 0
    # prepend original cipher blocks
    for i in range(0, block_start):
        output_bytes = output_bytes + cipher_blocks[i]
        num_blocks = num_blocks + 1
        
    # encrypt the blocks of the new plaintext and increment counter and nonce asap
    cipher = AES.new(key, AES.MODE_ECB)
    for i in range(block_start, block_end):
        keystream = struct.pack('<QQ', nonce, ctr)
        prngkey = cipher.encrypt(keystream)
        enc_list = base.equal_size_xor(bytearray(prngkey), newtext_blocks[i])
        enc_bytes = bytearray(''.join([chr(byte) for byte in enc_list]))
        output_bytes = output_bytes + enc_bytes
        num_blocks = num_blocks + 1
        ctr = ctr + 1
        if (ctr == 0x0):
            nonce = nonce + 1

    # append remaining blocks of the original ciphertext
    remaining  = len(cipher_blocks) - num_blocks
    for i in range(block_end + 1, remaining):
        output_bytes = output_bytes + cipher_blocks[i]
        num_blocks = num_blocks + 1
    
    cipher_output = ''.join([chr(byte) for byte in output_bytes])
    return cipher_output


if __name__ == "__main__":
    argc = len(sys.argv)
    if argc != 2:
        print "usage: %s filename" % (sys.argv[0])
    
    ciphertext = encrypt_file(sys.argv[1], key_base, nonce)   
    newtext = "A" * len(ciphertext)
    ciphertext2 = edit(ciphertext, key_base, 0, newtext)
    cx = base.equal_size_xor(bytearray(ciphertext), bytearray(ciphertext2))
    px = base.equal_size_xor(cx, bytearray(newtext))
    plaintext = ''.join([chr(byte) for byte in px])
    print plaintext

    