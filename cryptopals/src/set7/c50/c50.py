import sys
from Crypto.Cipher import AES


class Verifier:
    def __init__(self, key, iv):
        self.key = key
        self.iv = iv

    @staticmethod
    def pad(msg, ps = AES.block_size):
        return msg + (ps - (len(msg) % ps)) * chr(ps - (len(msg) % ps))

    def get_cbc_mac(self, msg):
        padded_msg = Verifier.pad(msg, AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        mac = cipher.encrypt(padded_msg)
        return mac[-AES.block_size:]

# helper for the attacker
def get_cbc_enc(key, iv, msg):
    padded_msg = Verifier.pad(msg, AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(padded_msg)

if __name__ == "__main__":
    key = "YELLOW SUBMARINE"
    iv = b'\x00'*AES.block_size
    original_js = "alert('MZA who was that?');\n"
    expected_digest = "296b8d7cb78a243dda4d0a61d33bbdd1"

    # validate cbc mac with expected value for known JS msg
    ver = Verifier(key, iv)
    actual_digest = ver.get_cbc_mac(original_js).encode('hex')
    assert(actual_digest == expected_digest)

    # forge message
    forged_header = "alert('Ayo, the Wu is back!');//"
    forged_header_digest = get_cbc_enc(key, iv, forged_header)[AES.block_size: 2*AES.block_size]

    # forge trailer as follows:
    # encrypt the header above using AES CBC and grab bytes 16:32 (since header is 32 bytes padded header will be 48 bytes. So cbc mac of header alone will include the padding which is N/A).
    # XOR the first 16 bytes of the original JS msg with the bytes obtained above. This ensures that when cbc mac of the final forged msg is computed, we set the state to the way it was for 
    # the cbc mac of the original JS msg. Now append the last 16 bytes of the original msg to the forged msg
    # forged_trailer = (cbc-encrypt(forged_header)[16:32] ^ original_msg[0:16]) + (original_msg[16:])
   
    ciphertext = get_cbc_enc(key, iv, original_js)
    forged_trailer = ''.join([chr( (b0 ^ b1) & 0xFF ) for b0, b1 in zip(bytearray(forged_header_digest), bytearray(original_js[:AES.block_size]))])
    forged_trailer += original_js[AES.block_size: ]

    forged_msg = forged_header + forged_trailer
    forged_digest = Verifier(key, iv).get_cbc_mac(forged_msg).encode('hex')
    
    if forged_digest != expected_digest:
        print "Error: expected %s but got %s" % (expected_digest, forged_digest)
        
        exit(-1)
    else:
        print "SUCCESS"
        print "original msg : %s , digest : %s" % (original_js, expected_digest)
        print "forged msg   : %s , digest : %s" % (forged_msg, forged_digest)


