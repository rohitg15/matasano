import sys
from Crypto.Signature import PKCS1_v1_5
from RsaHelper import RsaHelper
from oracle import RsaOracle
from bb import BleichenBackerAttacker
from crypto_math import CryptoMath
from Crypto.PublicKey import RSA
import asn1
import hashlib
from Crypto.Hash import SHA256
from Crypto.Util.asn1 import DerSequence, DerNull, DerOctetString, DerObjectId
from signature_forgery import SignatureForgery


def get_rsa_key(privkey_filename):
    with open(privkey_filename, "rb") as file:
            key_data = file.read()
    return RSA.importKey(key_data)


def bb_attack(rsa_key, input_message, is_pkcs):
    rsaOracle = RsaOracle(rsa_key)
    attacker = BleichenBackerAttacker(rsaOracle=rsaOracle, ciphertext=input_message, isMsgPkcs=is_pkcs)
    output_int = attacker.attack()
    output_bytes = CryptoMath.int_to_bytes(output_int)
    return output_bytes


def get_encoded_message(digest):
    # enc = asn1.Encoder()
    # enc.start()
    # enc.write(m_hash.oid)
    # enc.write(m_hash.digest())
    # return enc.output()
    # digestOid = DerObjectId()
    # digestOid.payload = b"2.16.840.1.101.3.4.2.1"
    
    # digestAlgorithm = DerSequence([
    #     digestOid.encode()
    # ])
    # digest = DerOctetString(m_hash.digest())
    # digestInfo = DerSequence([
    #     digestAlgorithm.encode(),
    #     digest.encode()
    # ]).encode()
    # return digestInfo
    return b'\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20' + digest

    #return m_hash.oid + m_hash.digest()


def verify_signature(rsa_key, m_hash, signature):
    pkcs = PKCS1_v1_5.new(rsa_key)
    return pkcs.verify(m_hash, signature)

def signature_forgery(rsa_key):
    #data = b'\x00\x01\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00I solved the ROBOT CTF / @RohitGuru'
    key_size_bytes = rsa_key.size() + 1 >> 3
    # pkcs = PKCS1_v1_5.new(rsa_key)
    # signature = pkcs.sign(m_hash)
    # hex_signature = CryptoMath.bytes_to_hex(signature)
    # print ("signature")
    # print (signature)
    # with open("/tmp/bb_out.txt", "w") as file:
    #     file.write(hex_signature)
    message = "Forging RSA signatures using bleichenbacker attack!"
    message_utf8 = message.encode('utf8')
    sig_gen = SignatureForgery()
    enc_message = sig_gen.get_bb_signature_forgery_payload(message_utf8, key_size_bytes)
    signature_bytes = bb_attack(rsa_key = rsa_key, input_message = enc_message, is_pkcs = False)
    signature_hex = CryptoMath.bytes_to_hex(signature_bytes)
    print ("Validating signature")
    if (verify_signature(rsa_key, SHA256.new(message_utf8), signature_bytes) == True):
        output = ' : '.join([message, signature_hex])
        print ("Signature Forgery succeeded : " + output)
    else:
        print ("Signature Forgery failed : " + str(signature_hex))
    
    
    
    
    # with open('/tmp/bb_test_signature.rs256', 'rb') as file:
    #     data = file.read()
    # print (CryptoMath.bytes_to_hex(data))
    # exit()

    #message = raw_message.encode('UTF-8')
    #m_hash = SHA256.new(message)
    # m_hash = hashlib.sha256(message)
    
    #print ("digest")
    #print (digest)
    # enc_digest = get_encoded_message(m_hash.digest())
    # data  = b'\x00\x01'
    # data += b'\xff' * (key_size_bytes - len(b'\x00\x01') -  len(b'\x00') - len(enc_digest))
    # data += b'\x00'
    # data += enc_digest


    # plain_sig = rsa_key.sign(data, b'\x01' * key_size_bytes)
    # plain_sig_bytes = CryptoMath.int_to_bytes(plain_sig[0])
    # plain_sig_hex = CryptoMath.bytes_to_hex(plain_sig_bytes)
    # print (plain_sig_hex)

    # print (verify_signature(rsa_key, SHA256.new(message), plain_sig_bytes))
    # exit()

    # int_data = CryptoMath.int_from_bytes(data)
    # dec_bytes = rsa_key.decrypt(data)
    # dec_hex = CryptoMath.bytes_to_hex(dec_bytes)
    # print (dec_hex)

    # pkcs = PKCS1_v1_5.new(rsa_key)
    # signature_original = pkcs.sign(m_hash)
    # signature_original_hex = CryptoMath.bytes_to_hex(signature_original)
    # print (signature_original_hex)
    # exit()

    #print (help(rsa_key.sign))
    # signature_hex = "46d3c4f2be6b2ef43032a54c60018e703b736302b450ae4293b59defda95abda7238b47296f46424bf5f6c6fc5185887e95222bffd343bd21ba6298bb84a8e2178bf2679580bf6e05a74c40147a77a9bc86ad117760f055c578b5d053b0c478d0b1e607b6fe0f59dd2cd98678deec1fd93e56513df7da7ffe8093db783e941df"
    # signature = CryptoMath.bytes_from_hex(signature_hex)
    # print ("signature verification:")
    # print (verify_signature(rsa_key, m_hash, signature))
    # exit()
    #data = enc_digest

    # exit()
    

if __name__ == "__main__":
    argc = len(sys.argv)
    if argc != 2:
        print ("Usage: ", sys.argv[0], " RSA_file_name")
        exit(-1)
    #numBits = int(sys.argv[1])
    rsa_file_name = sys.argv[1]
    rsa_key = get_rsa_key(rsa_file_name)
    # rsa_key = get_rsa_key(rsa_file_name)
    # rsaOracle = RsaOracle(rsa_key)

    # messageStr = "hello world!"
    # ciphertext = rsaOracle.encrypt(messageStr)

    # print ("message : ", messageStr)
    # print ("ciphertext : ", ciphertext)

    # # Initialize bleichenbacker's attack
    # attacker = BleichenBackerAttacker(rsaOracle=rsaOracle, ciphertext=ciphertext, isMsgPkcs=False)
    # plaintextInt = attacker.attack()
    # plaintextBytes = CryptoMath.int_to_bytes(plaintextInt)
    # plaintext = CryptoMath.bytes_to_hex(plaintextBytes)
    
    # # find first null byte and print all bytes after that
    # for i in range(len(plaintext)):
    #     if plaintext[i] == '\x00':
    #         print ("========== Decrypted Message ==========")
    #         print ("Decrypted Message : ", plaintext[i:])
    #         exit(0)

    signature_forgery(rsa_key)



    




