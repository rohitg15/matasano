import base
from Crypto.Cipher import AES
import Profile

def c9(text = "YELLOW SUBMARINE", block_size = 20):
    """
        implementing PKCS#7 padding
    """
    print base.pkcs7_pad(text,block_size)
    
    

def c10(filename):
    f = open(filename,"r")
    data = f.readlines()
    f.close()
    
    pad = "\x04"
    decoded_data = base.base64_to_hex(''.join(data).strip()).decode('hex')
    block_size = 16
    key = "YELLOW SUBMARINE"
    
    iv = ''.join(["\x00" for i in range(block_size)])
    blocks = [str(decoded_data[i*block_size : (i+1)*block_size]) for i in range(int(len(decoded_data)/block_size))]
    
    op = []
    size = len(blocks)
    for i in range(size):
        pt = base.AES_ECB_decrypt(blocks[i],key)
        res = base.equal_size_xor(bytearray(pt),bytearray(iv))
        res = base.bytearray_to_ASCII(res)
        op.append(res)
        iv = blocks[i]
    
    plaintext = base.pkcs7_unpad(''.join(op))
    print plaintext
        

def c11():
    input = "A" * 50
    key,iv,ciphertext = base.encryption_oracle(input)
    res = base.detect_block_cipher_mode(ciphertext)
    if res == True:
        print "ciphertext is in ECB mode"
        #decryptor = AES.new(key,AES.MODE_ECB)
        #print base.pkcs7_unpad(decryptor.decrypt(ciphertext))
    else:
        print "ciphertext is in CBC mode"
        #print "len:" , len(iv)
        #decryptor = AES.new(key,AES.MODE_CBC,iv)
        #print base.pkcs7_unpad(decryptor.decrypt(ciphertext))


def c12():
    unknown_string = ''
    with open("ip12.txt","r") as file:
        b64_unknown_string = file.read().strip('\n')

    unknown_string = base.base64_to_hex(b64_unknown_string).decode('hex')
    unknown_size = len(unknown_string)
    my_string = ""

    prefix = "A"*15
    known = ""

    while len(known) < unknown_size:
        known_size = len(known)
        pt = prefix +  unknown_string[known_size : ]
        ct = (base.AES_128_ECB(pt))
        for i in range(256):
            pt2 = prefix + chr(i) + unknown_string[known_size + 1 : ]
            ct2 = (base.AES_128_ECB(pt2))
            if ct2[0 : 16] == ct[0 : 16]:
                known += chr(i)
                break

    print known


def c13():
    input = "foo=bar&baz=qux&zap=zazzle"
    #print Profile.parse(input)


    input2 = "foo@bar.com"
    p = Profile.profile_for(input2)
    #print p , p.encode()
    
    # now we make role= appear at the end of a block

    legit_email = "abcde@bar.com"
    lp = Profile.profile_for(legit_email)
    legit_ciphertext = Profile.encrypt(lp.encode())

    # generate a fake profile where 'admin' appears at the begining of a block
    fake_email = "A"*10 + "admin"
    fp = Profile.profile_for(fake_email)
    fake_ciphertext = Profile.encrypt(fp.encode())

    # perform a cut and paste of the ECB ciphertexts obtained above
    ciphertext = legit_ciphertext[:32] + fake_ciphertext[16:32]

    fake_profile = Profile.decrypt(ciphertext)
    #print fake_profile
    new_profile = Profile.parse(Profile.decrypt(ciphertext))
    print new_profile

        
if __name__ == "__main__":
    #c9()
    #c10("ip10.txt")
    #c11()
    #c12()
    c13()