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
        size = len(ct) / bsize
        # divide the ciphertext into blocks - size 16
        blocks = [ct[i * bsize: (i + 1) * bsize] for i in range(size)]
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
    nonce = 0xdeadbeef
    for line in lines:
        plaintext = base.base64_to_hex(line.strip("\n")).decode('hex')
        ciphers.append(base.aes_ctr_encrypt(plaintext, key, nonce, 16))

    # get tbe minimum length cipher
    min_len = 10000000
    for cipher in ciphers:
        cur_len = len(cipher)
        if min_len > cur_len:
            min_len = cur_len

    # brute force each byte, column-wise, since each column entry
    # is encrypted with the same byte of the keystream as it is
    # repeated.
    key_bytes = [0x0] * min_len
    idx = 0
    for i in range(min_len):
        for brute in range(256):
            deciphered = [ord(cipher[i]) ^ brute for cipher in ciphers]
            if base.is_all_ascii(deciphered):
                key_bytes[idx] = brute
                idx += 1
                break

    # expand key now, start from 11th byte of key
    key_bytes = base.expand_ctr_key(ciphers[-12], key_bytes, 've', 10)
    key_bytes = base.expand_ctr_key(ciphers[-4], key_bytes, 'l', 12)
    key_bytes = base.expand_ctr_key(ciphers[3], key_bytes, 'ntury', 13)
    key_bytes = base.expand_ctr_key(ciphers[20], key_bytes, 'eet', 18)
    key_bytes = base.expand_ctr_key(ciphers[21], key_bytes, 'ful', 21)
    key_bytes = base.expand_ctr_key(ciphers[19], key_bytes, 'ill', 24)
    key_bytes = base.expand_ctr_key(ciphers[-7], key_bytes, 'rt', 27)
    key_bytes = base.expand_ctr_key(ciphers[-11], key_bytes, 'ht', 29)
    key_bytes = base.expand_ctr_key(ciphers[-15], key_bytes, 'd', 31)
    key_bytes = base.expand_ctr_key(ciphers[-13], key_bytes, 'd', 32)
    key_bytes = base.expand_ctr_key(ciphers[4], key_bytes, 'ead', 33)
    key_bytes = base.expand_ctr_key(ciphers[-3], key_bytes, 'n', 36)
    # decipher all ciphertexts now with the guessed key
    plaintexts = []
    for cipher in ciphers:
        pbytes = base.equal_size_xor(bytearray(cipher), key_bytes)
        plaintexts.append(''.join([chr(byte) for byte in pbytes]))
    print '\n'.join(plaintexts)


def c20(filename):
    """
    This program reads 40 strings and encrypts them under AES - CTR
    Then it attempts to crack the CTR mode without knowing the key
    using the fact that the nonce is repeated
    """
    with open(filename, "r") as file:
        lines = file.readlines()
    ciphers = []
    key = Random.get_random_bytes(16)
    nonce = 0xdeadbeef
    for line in lines:
        plaintext = base.base64_to_hex(line.strip("\n")).decode('hex')
        #print plaintext
        ciphers.append(base.aes_ctr_encrypt(plaintext, key, nonce, 16))

    # get tbe minimum length cipher
    min_len = 10000000
    for cipher in ciphers:
        cur_len = len(cipher)
        if min_len > cur_len:
            min_len = cur_len

    # brute force each byte, column-wise, since each column entry
    # is encrypted with the same byte of the keystream as it is
    # repeated.
    key_bytes = [0x0] * min_len
    idx = 0
    for i in range(min_len):
        for brute in range(256):
            deciphered = [ord(cipher[i]) ^ brute for cipher in ciphers]
            if base.is_all_ascii_expanded(deciphered):
                #print ''.join([chr(byte) for byte in deciphered])
                key_bytes[idx] = brute
                idx += 1
                break

    # expand key now, start from 11th byte of key
    key_bytes = base.expand_ctr_key(ciphers[8], key_bytes, 'irteenth', 13)
    key_bytes = base.expand_ctr_key(ciphers[4], key_bytes, 'e', 21)
    key_bytes = base.expand_ctr_key(ciphers[-9], key_bytes, 'rite', 22)
    key_bytes = base.expand_ctr_key(ciphers[-4], key_bytes, 'ing', 26)
    key_bytes = base.expand_ctr_key(ciphers[-8], key_bytes, 'out', 29)
    key_bytes = base.expand_ctr_key(ciphers[-26], key_bytes, 'and', 32)
    key_bytes = base.expand_ctr_key(ciphers[-17], key_bytes, 'ey', 35)
    key_bytes = base.expand_ctr_key(ciphers[-16], key_bytes, 'ence', 37)
    key_bytes = base.expand_ctr_key(ciphers[25], key_bytes, 'n', 41)
    key_bytes = base.expand_ctr_key(ciphers[29], key_bytes, 're', 42)
    key_bytes = base.expand_ctr_key(ciphers[-17], key_bytes, 'nt', 44)
    key_bytes = base.expand_ctr_key(ciphers[-11], key_bytes, 'n', 46)
    key_bytes = base.expand_ctr_key(ciphers[-24], key_bytes, 'dge', 47)
    key_bytes = base.expand_ctr_key(ciphers[5], key_bytes, 'ypse', 50)
    key_bytes = base.expand_ctr_key(ciphers[-23], key_bytes, 'y', 54)
    key_bytes = base.expand_ctr_key(ciphers[-18], key_bytes, 't', 55)
    key_bytes = base.expand_ctr_key(ciphers[16], key_bytes, 'ime', 56)
    key_bytes = base.expand_ctr_key(ciphers[-2], key_bytes, 'kin', 59)
    key_bytes = base.expand_ctr_key(ciphers[22], key_bytes, 'ate', 62)
    key_bytes = base.expand_ctr_key(ciphers[6], key_bytes, 'lty', 65)
    key_bytes = base.expand_ctr_key(ciphers[16], key_bytes, 'ght', 68)
    key_bytes = base.expand_ctr_key(ciphers[22], key_bytes, 'ate', 71)
    key_bytes = base.expand_ctr_key(ciphers[7], key_bytes, 'ssion', 74)
    key_bytes = base.expand_ctr_key(ciphers[-17], key_bytes, 'n', 79)
    key_bytes = base.expand_ctr_key(ciphers[8], key_bytes, 't', 80)
    key_bytes = base.expand_ctr_key(ciphers[5], key_bytes, 'e', 81)
    key_bytes = base.expand_ctr_key(ciphers[-28], key_bytes, 'lance', 82)
    key_bytes = base.expand_ctr_key(ciphers[4], key_bytes, 'row', 87)
    key_bytes = base.expand_ctr_key(ciphers[17], key_bytes, 'ble', 90)
    key_bytes = base.expand_ctr_key(ciphers[11], key_bytes, 'st', 93)
    key_bytes = base.expand_ctr_key(ciphers[-26], key_bytes, 'on', 95)
    key_bytes = base.expand_ctr_key(ciphers[26], key_bytes, 'rve', 97)
    key_bytes = base.expand_ctr_key(ciphers[-19], key_bytes, 'ull', 100)
    key_bytes = base.expand_ctr_key(ciphers[21], key_bytes, 'ace', 103)
    key_bytes = base.expand_ctr_key(ciphers[26], key_bytes, 'hole', 106)
    # decipher all ciphertexts now with the guessed key
    plaintexts = []
    for cipher in ciphers:
        pbytes = base.equal_size_xor(bytearray(cipher), key_bytes)
        plaintexts.append(''.join([chr(byte) for byte in pbytes]))
    print '\n'.join(plaintexts)


if __name__ == "__main__":
    # c17("ip17.txt")
    c20("../inputs/ip20.txt")
