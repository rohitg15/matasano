import sys
import os
script_path = "../base.py"
sys.path.append(os.path.abspath(script_path))
import base
from Crypto import Random

class Session:
    """ Class representing web session tokens """
    def __init__(self):
        self.key = Random.get_random_bytes(16)
        self.prepend_str = "comment1=cooking%20MCs;userdata"
        self.append_str = ";comment2=%20like%20a%20pound%20of%20bacon"
        self.admin_key = "admin=true"
    def escape(self, token):
        """ Escapes semi-colons in the token"""
        quoted_token = token.replace(";", "%3B")
        return quoted_token
    def get_encrypted_token(self, token):
        """ Returns AES CTR encrypted token """
        escaped_token = self.prepend_str + self.escape(token) + self.append_str
        encrypted_token = base.aes_ctr_manual_encrypt(escaped_token, self.key)
        return encrypted_token
    def is_admin(self, token):
        """ Decrypts the token and checks it corresponds to an administrator """
        decrypted_token = base.aes_ctr_manual_decrypt(token, self.key)
        kv_pairs = decrypted_token.split(";")
        for kv in kv_pairs:
            if kv.find(self.admin_key) != -1:
                return True
        return False
        
def get_admin_privilege(input_string):
    """ Perform bit flipping on CTR encrypted token """
    # get an encrypted cookie from the oracle
    session_state = Session()
    encrypted_token = session_state.get_encrypted_token(sys.argv[1])
    cipher_len = len(encrypted_token)
    input_bytes = bytearray(input_string)
    payload = ";admin=true"
    payload_bytes = bytearray(payload)
    payload_size = len(payload)

    # guess position where the input string begins by assuming every position as a starting point for the input_string
    for start in range(cipher_len):
        flipped_bytes = bytearray(encrypted_token)
        # flip each byte in the encrypted_token between [start, start + len(payload)]
        for i in range(payload_size):
            flipped_bytes[start + i] = flipped_bytes[start + i] ^ input_bytes[i] ^ payload_bytes[i]
        # attempt to gain administrative access with the oracle
        flipped_token = ''.join([chr(byte) for byte in flipped_bytes])
        if session_state.is_admin(flipped_token):
            print "%s worked! plaintext is at position %d" %  (flipped_token.encode('hex'), i)
            return True
    return False

if __name__ == "__main__":
    argc = len(sys.argv)
    if argc != 2:
        print "usage:%s input_string" , sys.argv[0]
        exit(0)
    if len(sys.argv[1]) < len(";admin=true"):
        print "minimum input length is %d", len(";admin=true")
    if get_admin_privilege(sys.argv[1]):
        print "Logged in as administrator"
    else:
        print "Failed to login as administrator"
