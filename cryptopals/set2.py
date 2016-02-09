import base

def c9(text = "YELLOW SUBMARINE",pad = "\x04",padding_len = 20):
    """
        implementing PKCS#7 padding
    """
    size = len(text)
    expected_size = ((size / padding_len) + 1) * padding_len
    rem = expected_size - size 
    padding = []
    padded_text = text
    if rem > 0 :
        padding = [pad for i in range(rem)]
        padded_text += ''.join(padding)
    return padded_text
    
    

def c10(filename):
    f = open(filename,"r")
    data = f.readlines()
    f.close()
    
    pad = "\x04"
    sdata = base.base64_to_hex(''.join(data).strip()).decode('hex')
    block_size = 16
    key = "YELLOW SUBMARINE"
    padded_data = c9(sdata,pad,block_size)
    
    iv = ''.join(["\x00" for i in range(block_size)])
    blocks = [str(padded_data[i*block_size : (i+1)*block_size]) for i in range(int(len(padded_data)/block_size))]
    
    op = []
    size = len(blocks)
    for i in range(size):
        pt = base.AES_ECB_decrypt(blocks[i],key)
        res = base.equal_size_xor(bytearray(pt),bytearray(iv))
        res = base.bytearray_to_ASCII(res)
        op.append(res)
        iv = blocks[i]
    
    for line in op:
        print line
        
        
        
if __name__ == "__main__":
    #c9()
    c10("ip10.txt")