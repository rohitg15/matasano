import sys
import struct
import base64
from Crypto.Cipher import AES
from Crypto import Random
from random import randint
import json




# convert base64 to hex
def base64_to_hex(data):
    return base64.b64decode(data).encode('hex')

# convert hex to base64
def hex_to_base64(data):
    return base64.b64encode(data.decode('hex'))

# convert ASCII string to bytearray
def ASCII_to_bytearray(data):
    return bytearray(data)

# convert bytearray to ASCII
def bytearray_to_ASCII(data):
    return ''.join([chr(byte) for byte in data])

#
def AES_ECB_encrypt(plain_text, bkey):
    """
        data    :   bytearray
        key     :   bytearray
    """
    cipher = AES.new(bkey, AES.MODE_ECB)
    return cipher.encrypt(plain_text)


def AES_ECB_decrypt(cipher_text, bkey):
    """
        data    :   bytearray
        key     :   bytearray
    """
    cipher = AES.new(bkey, AES.MODE_ECB)
    return cipher.decrypt(cipher_text)


def single_byte_xor(data, key):
    """
        data    :   bytearray
        key     :   single byte
    """
    return [byte ^ key for byte in data]


def brute_single_byte_xor(data, heuristic=0):
    """
        data    :   bytearray
    """
    for key in range(256):
        opbytes = [byte ^ key for byte in data]
        print bytearray_to_ASCII(opbytes), key


def score(plaintext):
    """
        plaintext   :   ASCII
    """
    char_freq = {}
    char_freq['a'] = 834
    char_freq['b'] = 154
    char_freq['c'] = 273
    char_freq['d'] = 414
    char_freq['e'] = 1260
    char_freq['f'] = 203
    char_freq['g'] = 192
    char_freq['h'] = 611
    char_freq['i'] = 671
    char_freq['j'] = 23
    char_freq['k'] = 87
    char_freq['l'] = 424
    char_freq['m'] = 253
    char_freq['n'] = 680
    char_freq['o'] = 770
    char_freq['p'] = 166
    char_freq['q'] = 9
    char_freq['r'] = 568
    char_freq['s'] = 611
    char_freq['t'] = 937
    char_freq['u'] = 285
    char_freq['v'] = 106
    char_freq['w'] = 234
    char_freq['x'] = 20
    char_freq['y'] = 204
    char_freq['z'] = 6
    char_freq[' '] = 2320

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
        score_table[plaintext] = (score(plaintext), key)

    pt = max(score_table, key=lambda k: score_table[k][0])
    return pt, score_table[pt][0], score_table[pt][1]


def repeating_key_xor(input, key):
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


def equal_size_xor(buf1, buf2):
    """
        buf1    :   bytearray
        buf2    :   bytearray
    """
    return [byte1 ^ byte2 for (byte1, byte2) in zip(buf1, buf2)]


def count_one(byte):
    count = 0

    while byte:
        count += 1
        byte &= byte - 1

    return count


def hamming_distance(b1, b2):
    """
        b1  :   bytearray
        b2  :   bytearray
    """
    count = 0
    bres = equal_size_xor(b1, b2)
    for byte in bres:
        count += count_one(byte)
    return count


def transpose(bdata, offset):

    size = len(bdata)
    op = [0] * size
    j = 0
    for i in range(size):
        idx = j + offset * (i % offset)
        if idx > size:
            j += 1
        op[i] = bdata[j]
    return op


def brute_repeating_key_xor(bdata):
    """
        bdata   :   bytearray
    """

    ht = {}
    for keysize in range(2, 41):
        left = bdata[0:keysize]
        right = bdata[keysize:keysize * 2]
        ham = hamming_distance(left, right) / keysize
        ht[keysize] = ham

    min_key_size = min(ht, key=lambda k: ht[k])
    return min_key_size


def pkcs7_pad(text, block_size=16):
    """
        performs a pkcs#7 padding and returns the modified text with
        appropriate padding bytes added
    """
    size = len(text)
    padding_len = (block_size - (size % block_size))
    return text + chr(padding_len) * padding_len


def pkcs7_unpad(text):
    """
        This function assumes that a PKCS#7 padding was already used on text
        and strips the padding bytes in order to return the original data
    """
    return text[0: -ord(text[-1])]


def encryption_oracle(input):
    rand_num1 = randint(5, 10)
    rand_num2 = randint(5, 10)
    encrypt_ecb = randint(0, 1)
    before = pkcs7_pad("", rand_num1)
    after = pkcs7_pad("", rand_num2)

    ciphertext = ''
    iv = ''
    key = Random.get_random_bytes(16)
    modified_input = before + input + after
    padded_input = pkcs7_pad(modified_input, 16)
    if encrypt_ecb == 1:
        # encrypt ECB
        encryptor = AES.new(key, AES.MODE_ECB)
        ciphertext = encryptor.encrypt(padded_input)
        print "ECB here"
    else:
        # encrypt CBC
        iv = Random.get_random_bytes(16)
        encryptor = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = encryptor.encrypt(padded_input)
        print "CBC here"

    return key, iv, ciphertext

# identify ECB/CBC mode by inspecting the ciphertext for repetitions
def detect_block_cipher_mode(ciphertext):
    block_size = 16
    blocks = [ciphertext[i * block_size : (i + 1) * block_size] for i in range(len(ciphertext) / block_size)]

    if len(set(blocks)) != len(blocks):
        # True implies ECB
        return True
    # False implies CBC
    return False


ecb_key = Random.get_random_bytes(16)


def AES_128_ECB(input):
    padded_input = pkcs7_pad(input, 16)
    encryptor = AES.new(ecb_key, AES.MODE_ECB)
    return encryptor.encrypt(padded_input)


def kvparser(input):
    kvpairs = input.split('&')
    d = {}
    for kv in kvpairs:
        key, value = kv.split('=')
        d[key] = value
    return json.dumps(d)


def sanitize(email):
    pos = email.find('&')
    if pos == -1:
        return email
    return sanitize(email[0: pos] + email[pos + 1:])


def profile_for(email):
    filtered_email = sanitize(email)
    uid = randint(0, 100)
    role = 'user'
    profile = 'email=' + filtered_email + "&" + "uid=" + uid + "&role=" + role


def quote(s):
    # replace ';'
    temp = s.replace(';', "%3B")
    return temp


# encrypt under AES CBC mode - byte flipping challenge
def enc_input(data):

    prefix = "comment1=cooking%20MCs;userdata="
    suffix = ";comment2=%20like%20a%20pound%20of%20bacon"
    plaintext = prefix + quote(data) + suffix
    cbc_key = ecb_key
    iv = "A" * 16
    encryptor = AES.new(cbc_key, AES.MODE_CBC, iv)
    padded_plaintext = pkcs7_pad(plaintext)
    return encryptor.encrypt(padded_plaintext)


# decrypt under AES CBC mode - byte flipping challenge
def dec_input(data):

    iv = "A" * 16
    cbc_key = ecb_key
    decryptor = AES.new(cbc_key, AES.MODE_CBC, iv)
    padded_plaintext = decryptor.decrypt(data)
    plaintext = pkcs7_unpad(padded_plaintext)
    return plaintext.find(";admin=true")


# function that checks for valid PKCS#7 padding
def is_padded(s):
    # if PKCS#7 padding were used then the last byte must indicate the same
    pad_chr = s[-1]
    size = ord(pad_chr)
    # the last size bytes must be equal to size for a valid PKCS#7 padding
    # if not, we have wrong padding here
    try:
        for i in range(size):
            if ord(s[-i - 1]) != size:
                return False
    except:
        return False
    return True


# AES CBC encryption oracle for challenge 17
def c17_encrypt_oracle(pt):
    key = ecb_key
    iv = Random.get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_pt = pkcs7_pad(pt)
    return cipher.encrypt(padded_pt), iv


# AES CBC decryption oracle for challenge 17
def c17_decrypt_oracle(ct, iv):
    key = ecb_key
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = cipher.decrypt(ct)
    return is_padded(pt)


# function for exploiting the padding oracle vulnerability
# recursively guess a 'tail' window of a block, by modifying the byte
# in the previous block. Use backtracking to assert that valid padding
# is not a false positive
def solve_po(cur, prev, pos, guess, padding, bsize, iv, sol):
    if pos < 0 or pos >= bsize:
        sol.append(guess[::-1])
        return True
    # pad the tail appropriately
    ptail = ''.join([ chr( ( ord(prev[i]) ^ ord(guess[bsize - i - 1]) ^ padding) % 256 ) for i in range(pos+1,bsize) ] )
    # brute force pos with all 256 possible bytes
    for byte in range(256):
        brute = chr((ord(prev[pos]) ^ padding ^ byte) % 256)
        temp = prev[:pos] + brute + ptail + cur
        # if a byte succeeds, it may be a False positive
        # so we recursively check using DFS, for all possible matches
        # we use backtracking to ensure that a wrong path is not
        # fully enumerated
        if c17_decrypt_oracle(temp, iv):
            if solve_po(cur, prev, pos - 1, guess + chr(byte), padding + 1, bsize, iv, sol):
                return True
    return False

# this is a class overriding the __call__ method
# so that its objects can be called as functions
# it maintains internal state - nonce, ctr
class Counter:
    def __init__(self, nonce=0x0):
        self.ctr = 0x0
        self.nonce = nonce
        self.counter = ''

    def __call__(self):
        self.counter = struct.pack('<Q', self.nonce)
        self.counter += struct.pack('<Q', self.ctr)
        self.ctr += 1
        if self.ctr == 0x0:
            self.nonce += 1
        return self.counter


# encrypt under AES in CTR mode
def aes_ctr_encrypt(plaintext, key, nonce, bsize=16):
    cipher = AES.new(key, AES.MODE_CTR, counter=Counter(nonce))
    return cipher.encrypt(plaintext)


# decrypt under AES in CTR mode
def aes_ctr_decrypt(ciphertext, key, nonce, bsize=16):
    cipher = AES.new(key, AES.MODE_CTR, counter=Counter(nonce))
    return cipher.decrypt(ciphertext)


# generic function to encrypt keystream and XOR with given text
# used for emulating AES CTR mode using AES ECB mode
def aes_ctr_crypt(text, key):
    bsize = 16
    btext = bytearray(text)
    blen = len(btext)
    size = 1 + (blen / bsize)
    blocks = [btext[i * bsize: (i + 1) * bsize] for i in range(size)]
    # compute AES CTR encryption of each part
    nonce = 0x0
    ctr = 0x0
    op = []
    cipher = AES.new(key, AES.MODE_ECB)
    for block in blocks:
        keystream = struct.pack('<QQ', nonce, ctr)
        keystream_bytes = bytearray(cipher.encrypt(keystream))
        op.extend(equal_size_xor(block, keystream_bytes))
        ctr += 1
        if ctr == 0x0:
            nonce += 1
    return ''.join([chr(byte) for byte in op])


# encrypt under AES in CTR mode
def aes_ctr_manual_encrypt(plaintext, key):
    return aes_ctr_crypt(plaintext, key)


# decrypt under AES in CTR mode
def aes_ctr_manual_decrypt(ciphertext, key):
    return aes_ctr_crypt(ciphertext, key)


# check if all characters in the text are ASCII
# expects a byte array
def is_all_ascii(text):
    charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-,;: "
    for byte in text:
        if chr(byte) not in charset:
            return False
    return True


def expand_ctr_key(cipher, key, guess, pos):
    cipher = bytearray(cipher)
    guess = bytearray(guess)
    return key[:pos] + ([cipher[pos + i] ^ guess[i] for i in range(len(guess))])
