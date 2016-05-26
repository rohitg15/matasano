import base
from Crypto.Cipher import AES
import Profile
import random

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
    unknown_ct = base.AES_128_ECB(unknown_string)
    prefix_size = len(unknown_ct)  - 1
    print prefix_size

    prefix = "A" * prefix_size
    known = ""

    while prefix_size > 0:
      pt = prefix + unknown_string
      ct = base.AES_128_ECB(pt)
      size = len(prefix) + len(known) + 1

      # brute force byte by byte
      for i in range(256):
        pt2 = prefix + known + chr(i)
        ct2 = base.AES_128_ECB(pt2)
        if ct[0:size] == ct2[0:size]:
          known += chr(i)
          break
      # adjust prefix by popping the last byte, since we know a new byte
      prefix = prefix[:-1]

      prefix_size = len(prefix)


    print known


def c13():
    input = "foo=bar&baz=qux&zap=zazzle"
    #print Profile.parse(input)


    input2 = "foo@bar.com"
    p = Profile.profile_for(input2)
    # print p , p.encode()

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
    # fake_profile = Profile.decrypt(ciphertext)
    # print fake_profile
    new_profile = Profile.parse(Profile.decrypt(ciphertext))
    print new_profile


def c13_enhanced():
  """
      In this enhanced mode of c13, we search for the appropriate sizes
      of the legitimate, fake profile's.

      i denotes the size of the legitimate email id that is created so that the
        word role= is positioned at the end of a block
      j denotes the size of the fake email id that we create to position admin at the begining of a new block

      since we do not know whether the keywordsd role=, admin are part fo the cookie, we search for all possible pairs i,j and perform the
        ECB cut and paste attack performed in part 13
        for one combiantion of i,j the keyword role= would be at the end of
        a block and the fake profile's 'admin' would be at the begining of
        a block. splicing the two and decrypting, generates a counterfeit
        profile with its privilege escalated

  """
  input = "foo=bar&baz=qux&zap=zazzle"
    #print Profile.parse(input)


  input2 = "foo@bar.com"
  p = Profile.profile_for(input2)

  # now we make 'role='' appear at the end of a block
  # since we do not know where eactly it occurs in the plaintext, we
  # search for all possible sizes for the email id such that 'role=' would
  # be pushed to the end of a block
  bsize = 16
  for i in range(bsize):
    legit_email = "a"*i + "@bar.com"
    lp = Profile.profile_for(legit_email)
    legit_ciphertext = Profile.encrypt(lp.encode())
    # generate a fake profile where 'admin' appears at the begining of a block
    # search all possible sizes from 0 through bsize, so that 'admin' falls
    # at the begining of a block
    for j in range(bsize):
      fake_email = "A"*j + "admin"
      fp = Profile.profile_for(fake_email)
      fake_ciphertext = Profile.encrypt(fp.encode())

      # perform a cut and paste of the ECB ciphertexts obtained above
      ciphertext = legit_ciphertext[:32] + fake_ciphertext[16:32]
      # print fake_profile
      new_profile = Profile.parse(Profile.decrypt(ciphertext))
      print new_profile , i , j, "\n"

      # grepping for the keyword admin reveals the profile with privilege
      # escalated to administrator


def c14():
  """
    This function performs leverages ECB's statelessnes to exploit ciphers
    where we have the form <RandomMessage, AttackerMessage, Cipher>

    The challenge encountered by an attacker in this case is that the
    attacker does not know the size of the random prefix, and therefore does
    not know where the ciphertext begins.

    To circumvent this, the attacker can inject 3 contiguous blocks with the
    same plaintext. There are 2 possible cases
      a)  If the random prefix is a multiple of block_size, then we get 3
          consecutive ciphertext blocks that have the same value
      b)  If the random prefix is not a multiple of the block_size, then we
          get 2 blocks that have the same value in the ciphertext

    In either case, we can read the consecutive blocks and identify the
    location where they end. This allows the attacker to identify the position
    of the actual ciphertext.

    Now the attacker can allocate another block whose last byte is filled by
    the ciphertext and brute force the ciphertext byte by byte as before.

  """
    # read the encrypted target string
  target_string = ''
  blk_size = 16
  with open("../inputs/ip12.txt", "r") as file:
      target_string = file.read().strip('\n')
  target_string = base.base64_to_hex(target_string).decode('hex')
  # generate a random prefix
  prefix_size = random.randint(0, 100)
  prefix = ''
  for i in range(prefix_size):
    prefix += chr(random.randint(0, 255))

  # create 3 blocks
  attacker_test = "a" * blk_size * 3
  test_cipher = base.AES_128_ECB(prefix + attacker_test + target_string)
  # detect 2 consecutive blocks
  pos = 0
  # divide the input into blocks of size blk_size
  blocks = [test_cipher[i*blk_size:(i+1)*blk_size] for i in range(len(test_cipher)/blk_size)]
  blocks_size = len(blocks)
  # look for 2 consecutive blocks that have the exact same value
  for i in range(blocks_size - 1):
    if blocks[i] == blocks[i+1]:
      pos = (i+1)*blk_size + blk_size
      print blocks[i] , i
      # check if there is a 3rd consecutive block
      if i < blocks_size - 2:
        if blocks[i+1] == blocks[i+2]:
          pos = (i+2)*blk_size + blk_size
          break
  # now we know where our blocks end, so we can reliably identify where the
  # ciphertext begins
  prefix_len = pos - blk_size*3
  while prefix_len < pos - blk_size*2:
    attack_size = blk_size
    attack_pad_size = attack_size - prefix_len % attack_size
    attacker_string = "A" * attack_pad_size
    # input to the AES ECB oracle will be plaintext
    # which has a random prefix, attacker controlled data, followed by
    # the target string that we intend to decrypt
    plaintext = prefix + attacker_string + target_string
    known = 0
    recover = ""
    unknown = len(target_string)
    pre = prefix + attacker_string
    sz = len(pre)
    print prefix_len, prefix_size
    # brute force each byte of the ciphertext
    # until we uncover the entire ciphertext
    while known < unknown:
      plaintext = pre[:-1] + target_string[known:]
      ciphertext = base.AES_128_ECB(plaintext)
      # brute force the byte
      for b in range(256):
        fake_plaintext = pre[:-1] + chr(b) + target_string[known + 1:]
        fake_ciphertext = base.AES_128_ECB(fake_plaintext)
        if fake_ciphertext[0:sz] == ciphertext[0:sz]:
          known += 1
          recover += chr(b)
          break
    print recover,"\n\n"
    prefix_len += 1


def c15(s):
  """
    This function attempts to check whether PKCS#7 padding is being used
    properly in the given string
    If the padding is wron, it raises an exception
  """
  # if PKCS#7 padding were used then the last byte must indicate the same
  pad_chr = s[-1]

  try:
    size = ord(pad_chr)
    Flag = True
    # the last size bytes must be equal to size for a valid PKCS#7 padding
    # if not, we have wrong padding here
    for i in range(size):
      if ord(s[-i-1]) != size:
        Flag = False
        break

    # raise exception if we don't have proper padding
    if Flag == True:
      print base.pkcs7_unpad(s)
      print s[:-ord(s[-1])]
    else:
      raise Exception


  except:
    # raise exception if any of the operations throws an exception
    print "exception!"
    raise Exception


def c16():
  """
    This function attempts to crack AES in CBC using bit flipping
  """
  data = ";adminttrue"
  blk_size = 16
  ciphertext = base.enc_input(data)
  # perform bit flipping here
  # we can see that the character at index 34 is the one we need to replace
  pos  = 34
  # the correspinding character in the previous block has to be modified
  # this works only if the target is in any block except the first
  # we want to change the character at position 35 to a ;
  prev_sc = ((pos/blk_size) - 1)*blk_size + (pos%blk_size)
  flip_sc = chr(ord(ciphertext[prev_sc]) ^ ord('B') ^ ord(';'))

  # we need to flip the character at index 41 to =
  # the corresponding position in the previous block is found as before
  pos = 40
  prev_eq = ((pos/blk_size) - 1)*blk_size + (pos%blk_size)
  flip_eq = chr(ord(ciphertext[prev_eq]) ^ ord('t') ^ ord('='))

  ct = ciphertext[:prev_sc] + flip_sc + ciphertext[prev_sc+1:prev_eq] + flip_eq + ciphertext[prev_eq+1:]

  op = base.dec_input(ct)
  if op == -1:
    print "failed: CBC bit flipping failed!"
  else:
    print "success: privilege escalated to admin"


if __name__ == "__main__":
    # c9()
    # c10("ip10.txt")
    # c11()
    #c12()
    #c13()
    #c13_enhanced()
    #c14()
    #c15("ICE ICE BABY\x04\x04\x04\x04")
    c16()
