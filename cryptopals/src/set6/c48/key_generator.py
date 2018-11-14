from Crypto.PublicKey import RSA
import sys



class RsaKeyGen:
    def __init__(self, num_bits = 1024, e = 65537):
        self.num_bits = num_bits
        self.e = e
        self.rsa = None

    def generate(self):
        self.rsa = RSA.generate(bits = self.num_bits, e = self.e)
        return self.rsa

    def __write_to_file__(self, file_name, data_bytes):
        with open(file_name, "wb") as file:
            file.write(data_bytes)
    
    def export_pub_key(self, file_name, out_format = 'PEM'):
        pub_key = self.rsa.publickey().exportKey(out_format)
        self.__write_to_file__(file_name, pub_key)
    
    def export_private_key(self, file_name, out_format = 'PEM'):
        priv_key = self.rsa.exportKey(out_format)
        self.__write_to_file__(file_name, priv_key)

    @staticmethod
    def import_rsa_keys(privkey_filename):
        with open(privkey_filename, "rb") as file:
            key_data = file.read()
        rsa = RSA.importKey(key_data)
        print (rsa.e)
        print (rsa.n)
        print (rsa.d)



if __name__ == "__main__":

    argc = len(sys.argv)
    if argc != 3:
        print ("Usage: %s public_key_filename private_key_filename" % (sys.argv[0]))
        exit(-1)

    pubkey_filename = sys.argv[1]
    privkey_filename = sys.argv[2]
    #key_gen = RsaKeyGen()
    #key_gen.generate()
    #key_gen.export_pub_key(pubkey_filename)
    #key_gen.export_private_key(privkey_filename)
    RsaKeyGen.import_rsa_keys(privkey_filename)
