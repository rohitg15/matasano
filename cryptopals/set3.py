import base
from Crypto import Random


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
    # print base.aes_ctr_decrypt(ciphertext, key, 16)
    print base.aes_ctr_manual_decrypt(ciphertext, key)


def c19(filename):
    """
    This program reads 40 strings and encrypts them under AES - CTR
    Then it attempts to crack the CTR mode without knowing the key
    using the fact that the nonce is repeated
    """
    with open(filename, "r") as file:
        lines = file.readlines()
    ciphers = []
    key = Random.get_random_bytes(16)
    for line in lines:
        plaintext = base.base64_to_hex(line.strip("\n")).decode('hex')
        ciphers.append(base.aes_ctr_encrypt(plaintext, key))


if __name__ == "__main__":
    # c17("ip17.txt")
    c18()
