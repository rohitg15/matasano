import sys
import zlib
from Crypto.Cipher import ARC4
from Crypto.Cipher import AES
from Crypto import Random


def formatRequest(P):
    return 'POST / HTTP/1.1\r\n' + \
            'Host: hapless.com\r\n' + \
            'Cookie: sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=\r\n' + \
            'Content-Length: %d\r\n' % len(P) + \
            '\r\n' + \
            P


def compress(payload):
    return zlib.compress(payload)

def encryptStream(payload):
    key = Random.get_random_bytes(256)
    return ARC4.new(key).encrypt(payload)

def pkcs7Pad(msg, blockSize = 16):
    remaining = len(msg) - (len(msg) % blockSize)
    return msg + chr(remaining) * remaining

def encryptAesCbc(payload):
    key = Random.get_random_bytes(16)
    iv = Random.get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, IV)
    return cipher.encrypt(pkcs7Pad(payload))

def oracle(msg):
    return len(encryptStream(compress(formatRequest(msg))))

def exploitCompressionOracle(sessionIdSize, base64Charset):
    guessedSessionId = ''
    prefix = ''

    while len(guessedSessionId) < sessionIdSize:
        bestLen = 5555
        for a in base64Charset:
            #for b in base64Charset:
            guess = prefix + a
            curLen = oracle("Cookie: sessionid=" + guess)
            if curLen < bestLen:
                bestLen = curLen
                guessedSessionId = guess
        prefix = guessedSessionId
        print prefix
    return guessedSessionId


if __name__ == "__main__":

    sessionId = "TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE="
    base64Charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    guessedSessionId =  exploitCompressionOracle(len(sessionId), base64Charset)
    print guessedSessionId[:-1] + '='