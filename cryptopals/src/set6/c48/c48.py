import sys
from RsaHelper import RsaHelper
from oracle import RsaOracle
from bb import BleichenBackerAttacker
from crypto_math import CryptoMath


if __name__ == "__main__":
    argc = len(sys.argv)
    if argc != 2:
        print ("Usage: ", sys.argv[0], " RSA-Modulus-Bit-Length\n")
        exit(-1)
    numBits = int(sys.argv[1])
    oracle = RsaOracle(numBits)

    messageStr = "hello world!"
    ciphertext = oracle.encrypt(messageStr)

    print ("message : ", messageStr)
    print ("ciphertext : ", ciphertext)

    # Initialize bleichenbacker's attack
    attacker = BleichenBackerAttacker(rsaOracle=oracle, ciphertext=ciphertext, isMsgPkcs=False)
    plaintextInt = attacker.attack()
    plaintextBytes = CryptoMath.int_to_bytes(plaintextInt)
    plaintext = CryptoMath.bytes_to_hex(plaintextBytes)
    print (plaintext)




