import base



def c17(filename):
    """
    This program performs the padding oracle attack
    on AES cipher in CBC mode
    """
    with open(filename, "r") as file:
        lines = file.readlines()

    bsize = 16
    for line in lines:
        # convert each line to ASCII
        data = base.base64_to_hex(line).decode('hex')
        # obtain ciphertext from encryption oracle
        # this is equivalent to getting a cookie
        ct, iv = base.c17_encrypt_oracle(data)
        # divide the ciphertext into blocks - size 16
        blocks = [ct[i * bsize : (i + 1) * bsize] for i in range(len(ct) / bsize)]
        sol = []
        prev = iv
        padding = 0x1
        for block in blocks:
            # decrypt current block (cur)
            # by modifying previous block (prev)
            base.solve_po(block, prev, bsize - 1, "", padding, bsize, iv, sol)
            prev = block
        print ''.join(sol)


def c18():
    """
    This program performs AES decryption in CTR mode
    """
    ciphertext = base.base64_to_hex("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==").decode('hex')
    key = "YELLOW SUBMARINE"
    bkey = bytearray("YELLOW SUBMARINE")
    print base.aes_ctr_decrypt(ciphertext, key, 16)


if __name__ == "__main__":
  #c17("ip17.txt")
  c18()
