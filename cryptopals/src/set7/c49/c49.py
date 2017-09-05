import sys
from Crypto.Cipher import AES
from Crypto import Random
import base64



class CryptoHelper:
    def __init__(self, key, iv = None):
        self.key = key
        self.iv = iv

    @staticmethod
    def pad(msg, ps):
        return msg + (ps - (len(msg) % ps)) * chr(ps - (len(msg) % ps))

    def get_signature(self, msg, iv):
        """compute a cbc mac of the msg as a signature"""
        enc_cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return enc_cipher.encrypt(CryptoHelper.pad(msg, AES.block_size))[-AES.block_size:]
    
    def is_signature_valid(self, msg, signature, iv):
        """validate the presented signature against the expected signature."""
        expected_signature = self.get_signature(msg, iv)
        is_valid = (len(expected_signature) == len(signature))
        for b1,b2 in zip(bytearray(expected_signature), bytearray(signature)):
            if b1 != b2:
                is_valid = False
        return is_valid

class ApiServer:
    def __init__(self, key, iv = None):
        self.key = key
        self.iv = iv
        self.cipher = CryptoHelper(key, iv)

    def process_transaction(self, msg):
        kvp = parse_request(msg)
        from_addr = kvp['from']
        to_addr = kvp['to']
        amount = kvp['amount']
        # assume base64 encoded
        signature = base64.b64decode(kvp['sig'])
        iv = base64.b64decode(kvp['iv'])
        msg_to_sign = "from:" + from_addr + "&to:" + to_addr + "&amount:" + amount
        
        if self.cipher.is_signature_valid(msg_to_sign, signature, iv) == False:
            print "Unauthorized request!"
            return False
        print "transferred %s from %s to %s" % (amount, from_addr, to_addr)
        return True
        
class WebServer:
    def __init__(self, key, iv = None):
        self.key = key
        self.iv = iv
        self.cipher = CryptoHelper(key, iv)
        self.api = ApiServer(key, iv)

    # contrived example where the web server allows from address as mallory and nobody else
    def send_money(self, to_addr, amount):
        from_addr = "bob"
        msg_to_sign = "from:" + from_addr + "&to:" + to_addr + "&amount:" + str(amount)
        if self.iv == None:
            self.iv = Random.get_random_bytes(AES.block_size)
        signature = self.cipher.get_signature(msg_to_sign,self.iv)
        request = msg_to_sign + "&iv:" + base64.b64encode(self.iv) + "&sig:" + base64.b64encode(signature)
        self.api.process_transaction(request)
        return request
        

def parse_request(msg):
    # assume that & is used as a separator
    params = msg.split('&')
    kvp = {}
    for param in params:
        # assume each parameter is of the form key = value
        pair = param.split(':')
        kvp[pair[0]] = pair[1]
    return kvp

def compute_fake_iv(forged_msg, target_msg):
    forged_iv = bytearray()
    for b1,b2 in zip(bytearray(forged_msg), bytearray(target_msg)):
        forged_iv.append( (b1 ^ b2) & 0xFF )
    return (''.join([chr(b) for b in forged_iv]))[0:AES.block_size]

if __name__ == "__main__":


    # initialize key
    key_size_bytes = 16
    key = Random.get_random_bytes(key_size_bytes)
    from_addr = 'bob'
    to_addr = 'eve'
    

    # Attack 1 : initiate transaction with a fixed IV (forged to the reverse transaction i.e from eve to bob)
    #            and send money to eve. Now take it back by forging a transaction from eve to bob with the signature
    #            from transaction 1. This is because the IV that we forged is XORd with the initial message to modify 
    #            the message to the forged_message. In some sense, we are fixing the signature using a forged IV
    # forge IV

    forged_msg = "from:" + to_addr + "&to:" + from_addr + "&amount:" + '10000'
    target_msg = "from:" + from_addr + "&to:" + to_addr + "&amount:" + '10000'
    forged_iv = compute_fake_iv(forged_msg, target_msg)

    # send benign request, with forged IV and capture signature
    web_client = WebServer(key, forged_iv)
    request = web_client.send_money('eve', 10000)
    kvp = parse_request(request)

    new_iv = b'\x00' * AES.block_size
    forged_request = forged_msg + "&iv:" + base64.b64encode(new_iv) + "&sig:" + kvp['sig']
    api_client = ApiServer(key)
    api_client.process_transaction(forged_request)


        
        


