import sys
import struct
import base64
from Crypto.Cipher import AES


def base64_to_hex(data):
   return base64.b64decode(data).encode('hex')
   
def hex_to_base64(data):
    return base64.b64encode(data.decode('hex'))
    
def ASCII_to_bytearray(data):
    return bytearray(data)
    
def bytearray_to_ASCII(data):
    op = [chr(byte) for byte in data]
    return ''.join(op)
    
    
def AES_ECB_encrypt(plain_text,bkey):
    """
        data    :   bytearray
        key     :   bytearray
    """
    cipher = AES.new(bkey,AES.MODE_ECB)
    return cipher.encrypt(plain_text)
 
def AES_ECB_decrypt(cipher_text,bkey):
    """
        data    :   bytearray
        key     :   bytearray
    """
    cipher = AES.new(bkey,AES.MODE_ECB)
    return cipher.decrypt(cipher_text)
 
 
def single_byte_xor(data,key):
    """
        data    :   bytearray
        key     :   single byte
    """
    return [byte ^ key for byte in data]
    
def brute_single_byte_xor(data,heuristic = 0):
    """
        data    :   bytearray
    """
    for key in range(256):
        opbytes = [byte ^ key for byte in data]
        print bytearray_to_ASCII(opbytes) , key



def score(plaintext):
    """
        plaintext   :   ASCII
    """
    char_freq = {}
    char_freq['a']=834
    char_freq['b']=154
    char_freq['c']=273
    char_freq['d']=414
    char_freq['e']=1260
    char_freq['f']=203
    char_freq['g']=192
    char_freq['h']=611
    char_freq['i']=671
    char_freq['j']=23
    char_freq['k']=87
    char_freq['l']=424
    char_freq['m']=253
    char_freq['n']=680
    char_freq['o']=770
    char_freq['p']=166
    char_freq['q']=9
    char_freq['r']=568
    char_freq['s']=611
    char_freq['t']=937
    char_freq['u']=285
    char_freq['v']=106
    char_freq['w']=234
    char_freq['x']=20
    char_freq['y']=204
    char_freq['z']=6
    char_freq[' ']=2320

    points = 0
    plaintext = plaintext.lower()
    for char in plaintext:
        if char_freq.get(char) is not None:
            points += char_freq[char]
            
    return points
    
def brute_single_byte_xor_heuristic(data):
    """
        data    :   bytearray
    """
    score_table = {}
    for key in range(256):
        opbytes = [byte ^ key for byte in data]
        plaintext = bytearray_to_ASCII(opbytes)
        score_table[plaintext] = (score(plaintext),key)
        
    pt = max(score_table,key=lambda k: score_table[k][0])
    return pt, score_table[pt][0], score_table[pt][1]
    
    
def repeating_key_xor(input,key):
    """
        input   :   bytearray
        key     :   bytearray
    """
   
    sz_input = len(input)
    sz_key = len(key)
    op = []
    for i in range(sz_input):
        op.append(input[i] ^ key[i % sz_key])
    return op
        
def equal_size_xor(buf1,buf2):
    """
        buf1    :   bytearray 
        buf2    :   bytearray
    """
    return [byte1 ^ byte2 for (byte1,byte2) in zip(buf1,buf2)]
    


def count_one(byte):
    count = 0
    
    while byte:
        count += 1
        byte &= byte -1

    return count
    
def hamming_distance(b1,b2):
    """
        b1  :   bytearray
        b2  :   bytearray
    """
    count  = 0
    bres = equal_size_xor(b1,b2)
    for byte in bres:
        count += count_one(byte)
    return count
    

def transpose(bdata,offset):
   
    size = len(bdata)
    op = [0] * size
    j = 0
    for i in range(size):
        idx = j + offset * (i%offset)
        if idx > size:
            j += 1
        op[i] = bdata[j]
    return op
    
    
def brute_repeating_key_xor(bdata):
    """
        bdata   :   bytearray
    """
    
    ht = {}
    for keysize in range(2,41):
        left = bdata[0:keysize]
        right = bdata[keysize:keysize*2]
        ham = hamming_distance(left,right) / keysize
        ht[keysize] = ham
        
    min_key_size = min(ht, key=lambda k: ht[k])
    return min_key_size    
    
        