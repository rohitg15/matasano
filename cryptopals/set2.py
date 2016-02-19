import base

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
        
        
if __name__ == "__main__":
    #c9()
    c10("ip10.txt")