from Crypto.Cipher import ARC4
from Crypto import Random
import base64


class RC4Cipher:
    @staticmethod
    def encrypt(prefix, message):
        key = Random.get_random_bytes(16)
        return (key, ARC4.new(key).encrypt(prefix + message))

    @staticmethod
    def decrypt(key, ciphertext):
        return ARC4.new(key).decrypt(ciphertext)


def attack_byte(message, idx, num_trials = 2 ** 24):
    padding = 'A' * (15 - idx)
    char_map = {char : 0 for char in range(256)}
    for i in range(num_trials):
        _, ct = RC4Cipher.encrypt(padding.encode(), message)
        c_val = ct[15] ^ 0xf0   # RC4 bias Zr = r for r = 0 mod keySize
        char_map[c_val]+=1
    max_char = max(char_map.keys(), key=(lambda k: char_map[k]))
    return max_char


if __name__ == "__main__":
    cookie = base64.b64decode("QkUgU1VSRSBUTyBEUklOSyBZT1VSIE9WQUxUSU5F")
    
    # build bias maps
    guess = []
    for i in range(len(cookie)):
        guessed_val = attack_byte(cookie, i)
        print (guessed_val)
        guess.append(chr(guessed_val))
    
    print (''.join(guess))

