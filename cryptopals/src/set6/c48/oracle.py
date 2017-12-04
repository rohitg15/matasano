
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
            Returns     :   ByteString containing RSA encrypted ciphertext
        """
        return super(RsaOracle, self).encrypt(messageStr)

    def get_response(self, ciphertextBytes):
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
            decrypted = super(RsaOracle, self).decrypt(ciphertextBytes)
            print("Decryption succeeded!")
            return True
        except:
            False

