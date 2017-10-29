import sys
import struct
from Crypto.Cipher import AES
from Crypto import Random
import hashlib



def Pad(msg, blockSize = 16):
    if (len(msg) % blockSize == 0):
        return msg
    msgLen = len(msg)

    # padding = msg + 0x01 + 0x00....msgLen
    numZeroes = blockSize - 4 - 1 - (msgLen % blockSize)
    return msg + struct.pack('>B', 0x01) + (b'\x00' * numZeroes) + struct.pack('>I', msgLen)

class HashProvider:
    def __init__(self):
        self.blockSize = AES.block_size
        self.hashLength = 2
        self._ho = b'\x01\x02'

    def __MerkleDamgard__(self, msg, h, func):

        # Assuming the message to be padded to AES block size
        paddedBlocks = [msg[i * self.blockSize : (i + 1) * self.blockSize] for i in range(len(msg) / self.blockSize)]
        if (len(h) != self.hashLength):
            raise("Hash length must be equal to %d", self.hashLength)
        
        for msgBlock in paddedBlocks:
            h = func(msgBlock, h)
        return h[:self.hashLength]
    
    def __AesEncrypt__(self, paddedMsg, key):
        key = Pad(key)
        if (len(paddedMsg) % AES.block_size != 0):
            raise("AES msg block padding error. block of size %d is not a multiple of %d", len(msg) , AES.block_size)
        cipher = AES.new(key, AES.MODE_ECB)
        return cipher.encrypt(paddedMsg)[:self.hashLength]

    def GetHash(self, msg, h0 = None):
        if h0 is None:
            h0 = self._ho
        return self.__MerkleDamgard__(msg = msg, h = h0, func = self.__AesEncrypt__)



class ExpensiveHash:
    def __init__(self, hashSize = 3):
        self.hashSize = 3
    
    def GetMd5(self, msg):
        return hashlib.md5(msg).digest()[:self.hashSize]

class CombinedHash:
    def __init__(self, hp, eh):
        self.f = hp
        self.g = eh
    
    def GetHash(self, msg):
        cheapHash = self.f.GetHash(msg)
        expensiveHash = self.g.GetMd5(msg)
        assert(len(cheapHash) == self.f.hashLength)
        assert(len(expensiveHash) == self.g.hashSize)
        return cheapHash + b'' + expensiveHash


class CollisionFinder:
    def __init__(self):
        self.blockSize = AES.block_size
        self.hashLength = 2
        self.hp = HashProvider()
        
    # since the size of the state is only 16 bits we can brute-force a collision
    def FindBruteForceCollision(self, state):
        collisions = {}
        for b0 in range(256):
            for b1 in range(256):
                msg = ''.join([chr(b0), chr(b1)])
                msg = Pad(msg)
                digest = self.hp.GetHash(msg, state)
                if collisions.has_key(digest):
                    return msg, collisions[digest], digest
                collisions[digest] = msg
        return None, None, None

    # if x,y collide in stage 1 and p,q collide in stage 2
    # then x + p, x + q, y + p, y + q are also collisions
    # construct all such groupings    
    def __GetAllMultiCollisions__(self, collisions, i, partial, multiCollisions):
        numCollisions = len(collisions)
        if (i > numCollisions):
            return
        if (i == numCollisions):
            byteString = ''.join([ch for ch in partial])
            multiCollisions.append(byteString)
            return

        # collisions[i] has 2 messages always
        for msg in collisions[i]:
            partial.append(msg)
            self.__GetAllMultiCollisions__(collisions, i + 1, partial, multiCollisions)
            partial.pop()
    
    def f(self, n, state = b'\x01\x02'):
        collisions = []
        # To find 2 ** n collisions we need n steps
        for i in range(n):
            prevState = state
            x, y, state = self.FindBruteForceCollision(state)
            #print x.encode('hex'), y.encode('hex'), state.encode('hex'), prevState.encode('hex')
            if x is None or y is None or state is None:
                raise('Error: could not find collision!')
            collisions.append([x, y])
        
        multiCollisions = []
        partial = []
        self.__GetAllMultiCollisions__(collisions, 0, partial, multiCollisions)

        # Validate all multi-collisions
        prev = ''
        for m in multiCollisions:
            if not prev:
                prev = self.hp.GetHash(Pad(m, AES.block_size))
            else:
                assert(prev == self.hp.GetHash(Pad(m, AES.block_size)))
        return multiCollisions

    
    @staticmethod
    def PrettyPrint(h):
        return ''.join([hex(b)[2:] for b in bytearray(h)])


if __name__ == "__main__":
    # Test cheap hash
    h = HashProvider()
    paddedMsg = Pad("Hello World!", AES.block_size)
    assert(h.GetHash(paddedMsg) == h.GetHash(paddedMsg))
    assert(len(h.GetHash(paddedMsg)) == h.hashLength)
    
    # Test combined hash
    f = HashProvider()
    g = ExpensiveHash(3)
    ch = CombinedHash(f, g)
    assert(ch.GetHash(paddedMsg) == ch.GetHash(paddedMsg))
    assert(len(ch.GetHash(paddedMsg)) == f.hashLength + g.hashSize) 

    # To get 2 ** 16 collisions we only need 16 calls to f(), Test Collision generator
    cf = CollisionFinder()
    numCalls = 16
    collisions = cf.f(n = numCalls)
    assert (len(collisions) == 2 ** numCalls)
    
    # attack combined hash now, by attacking the weaker hash f
    # f -> 16 bits, g -> 24 bits
    # Idea is to generate 2 ** (24/2) collisions in f(), which could contain a collision in g()
    # if not, we can double the number of collisions in f() and look for collisions in g() with greater probability

    cf = CollisionFinder()
    f = HashProvider()
    g = ExpensiveHash(3)
    numCalls = g.hashSize * 8 / 2
    while True:
        fCollisions = cf.f(n = numCalls)
        gCollisions = {}
        for msg in fCollisions:
            digest = g.GetMd5(msg)
            if gCollisions.has_key(digest):
                print msg.encode('hex'), gCollisions[digest].encode('hex'), digest.encode('hex')
                #assert(f.GetHash(msg) == f.GetHash(gCollisions[digest]))
                assert(g.GetMd5(msg) == g.GetMd5(gCollisions[digest]))
                print "numCalls to collision finder: %d" % (numCalls)
                exit(0)
            gCollisions[digest] = msg
        # if we reach here, we haven't found a collision in g, double number of hashes that we must get
        numCalls = numCalls + 1
        print "increasing to " , (numCalls)






    



        


