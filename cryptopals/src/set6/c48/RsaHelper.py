from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from crypto_math import CryptoMath


class CryptographicException(Exception):
    def __init__(self, message):
        Exception.__init__(self, message)
        self.message = message

class RsaHelper:
    def __init__(self, numBits, e = 65537):
        """
            Initialize RSA cryptosystem with PKCS#1.5 padding

            numBits :   Integer denoting nuber of bits of RSA modulus
            e       :   Integer denoting RSA public exponent
        """
        self.rsa = RSA.generate(bits = numBits, e = e)
        self.cipher = PKCS1_v1_5.new(self.rsa)


    def __init__(self, rsa_key):
        """
            Initializes RSA cryptosystem with the given key

            rsa_key :   object of type Crypto.PublicKey.RSA with public and private keys
        """
        self.rsa = rsa_key
        self.cipher = PKCS1_v1_5.new(self.rsa)

    def encrypt(self, messageStr):
        """
            Encrypt messageStr using RSA. messageStr is padded using 
            PKCS#1.5 before encryption.

            messageStr  :   String denoting input message
            Returns     :   bytearray containing RSA encrypted ciphertext
        """
        return self.cipher.encrypt(CryptoMath.string_to_bytes(messageStr))

    def decrypt(self, ciphertextBytes):
        """
            Decrypt given ciphertext using RSA. Message is assumed to
            be padded using PKCS#1.5

            ciphertextBytes :   Byte array denoting encrypted ciphertext
            Returns         :   String containing plaintext after stripping
                                out the PKCS#1.5 padding
            throws          :   CryptographicException if the padding in the
                                decrypted string is invalid.
        """
        sentinel = "SENTINEL1337"
        decryptedStr = self.cipher.decrypt(ciphertextBytes, sentinel)
        if decryptedStr == sentinel:
            raise CryptographicException("Invalid PKCS1.5 padding")
        return decryptedStr


if __name__ == "__main__":
    message = "hello world!"
    cipher = RsaHelper(numBits = 1024, e = 65537)
    ciphertext = cipher.encrypt(message)
    print ("Ciphertext : ", ciphertext)

    plaintext = cipher.decrypt(ciphertext)
    print ("Plaintext : ", plaintext)
