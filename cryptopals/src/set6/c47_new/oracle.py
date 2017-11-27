
# import class implementing RSA encryption
from RsaHelper import RsaHelper
from crypto_math import CryptoMath

class RsaOracle(RsaHelper):
    """
        RsaOracle subclasses RsaHelper to abstract implementation
        details from the callers.
    """
    def __init__(self, numBits, e = 65537):
        super(RsaOracle, self).__init__(numBits, e)
        self.size_bytes = self.rsa.n.bit_length() // 8


    @staticmethod
    def prepare_message(mInteger):
        """
            Prepares input message in the appropriate format expected by the
            underlying RSA oracle's implementation

            mInteger    :   integer denoting RSA ciphertext
            Returns     :   message in format expected by response method
        """
        return CryptoMath.int_to_bytes(mInteger)

    def get_public_key(self):
        """
            Gets the RSA public key of the client - RsaHelper

            Returns :   object of type Crypto.PublicKey.RSA
        """
        return self.rsa.publickey()

    def encrypt(self, messageStr):
        """
            Encrypt messageStr using RSA. messageStr is padded using 
            PKCS#1.5 before encryption.

            messageStr  :   String denoting input message
            Returns     :   String containing RSA encrypted ciphertext
        """
        return self.cipher.encrypt(messageStr)

    def response(self, ciphertextBytes):
        """
            Get response from oracle and return decrypted plaintext.
            Message is assumed to be padded using PKCS#1.5.

            This method takes care of marshalling the ciphertextBytes
            as required by the underlying implementation of RSA oracle.

            ciphertextBytes     :   Bytearray denoting encrypted ciphertext
            Returns             :   Boolean indicating whether the padding
                                in the decrypted string was invalid.
        """
        try:
            decrypted = self.cipher.decrypt(ciphertextBytes)
            return True
        except:
            False

# from Crypto.Util.number import getPrime
# from Crypto import Random
# from random import randint
# from crypto_math import RSAHelper
# from crypto_math import CryptoMath

# class RSAKeyGen:
#     def __init__(self, p, q, e):
#         self.p = p
#         self.q = q
#         self.e = e

# class RSAOracle(RSAHelper):
#     """RSA helper that uses PKCS1.5 padding for RSA encryption """
#     def __init__(self, p, q, e):
#         RSAHelper.__init__(self,p, q, e)
#         self.size_bytes = (self.n.bit_length() + 1) // 8
#         #print "num bytes of modulus %d" % (self.size_bytes)

    # def is_padding_valid(self, plaintext):
    #     if (len(plaintext) != self.size_bytes):
    #         return False
    #     bplaintext = bytearray(plaintext)

    #     if bplaintext[0] != 0 and bplaintext[1] != 2:
    #         return False
    #     is_zero_found = False
    #     for i in range(len(bplaintext[2:])):
    #         if bplaintext[i] == 0:
    #             is_zero_found = True
    #             break
    #     return is_zero_found

#     def __get_pkcs15_padded_int__(self, plaintext):
#         # 3 comes from the 2 initial bytes and the mandatory zero byte between the padding and the payload
#         padded_bytes = b'\x00\x02' + (self.size_bytes - len(plaintext) - 3)*b'\xff' + b'\x00' + bytearray(plaintext)
#         padded_str = ''.join([chr(b) for b in padded_bytes])
#         return int(padded_str.encode('hex'), 16)

#     def __unpad__(self, plaintext):
#         if len(plaintext) & 1 != 0:
#             plaintext = b'\x00' + plaintext
#         if self.is_padding_valid(plaintext) == False:
#             raise Exception('Error: invalid RSA PKCS1.5 padding!')
#         bplaintext = bytearray(plaintext[2:])
#         start_idx = -1
#         for i in range(len(bplaintext)):
#             if bplaintext[i] == 0x00:
#                 start_idx = i
#                 break
#         return ''.join([chr(b) for b in bplaintext[start_idx + 1: ]])

#     def rsa_encrypt(self, plaintext):
#         plaintext_int = self.__get_pkcs15_padded_int__(plaintext)
#         return self.encrypt(plaintext_int)

#     def rsa_decrypt(self, ciphertext):
#         plaintext_int = self.decrypt(ciphertext)
#         plaintext_hex_str = CryptoMath.lint_to_hex_str(plaintext_int)
#         return self.__unpad__(plaintext_hex_str.decode('hex'))

