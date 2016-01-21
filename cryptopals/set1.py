import base


def c1():
    input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    if expected == base.hex_to_base64(input):
        print "c1 successful!"
    else :
        print "c1 failed!"

def c2():
    input1 = "1c0111001f010100061a024b53535009181c".decode('hex')
    input2 = "686974207468652062756c6c277320657965".decode('hex')
    
    b1 = bytearray(input1)
    b2 = bytearray(input2)
    b = base.equal_size_xor(b1,b2)
    
    op = base.bytearray_to_ASCII(b).encode('hex')
    expected = "746865206b696420646f6e277420706c6179"
    if op == expected:
        print "c2 successful!"
    else :
        print "c2 failed!"
        
        
def c3():
    input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736".decode('hex')
    binput = bytearray(input)
    
    print base.brute_single_byte_xor_heuristic(binput)
        
    # answer    :   "Cooking MC's like a pound of bacon", key = 88
    
    
def c4(filename):
    f = open(filename, "r")
    data = f.readlines()
    f.close()
    
    points = {}
    for line in data:
        plaintext,score,key = base.brute_single_byte_xor_heuristic(bytearray(line.strip('\n').decode('hex')))
        points[plaintext] = (score,key)
        
    pt = max(points, key=lambda k: points[k][0])
    print (pt, points[pt][0] , points[pt][1])
    # answer    :   "Now that the party is jumping" , key = 53
    
if __name__ == "__main__":
    c1()
    c2()
    c3()
    c4("ip4.txt")
    