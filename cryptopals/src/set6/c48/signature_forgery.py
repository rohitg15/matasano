import hashlib

class SignatureForgery:
    oids = {
        "sha256" : b'\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20'
    }

    def __get_der_encoded_message__(self, hash_obj):
        if SignatureForgery.oids.get(hash_obj.name) is None:
            raise('Error: Unsupported hash algorithm.')
        return SignatureForgery.oids.get(hash_obj.name) + hash_obj.digest()
    
    def get_pkcs1_message(self, message, hash_obj, payload_len):
        hash_obj.update(message)
        enc_digest = self.__get_der_encoded_message__(hash_obj)
        payload = b'\x00\x01'
        payload += b'\xff' * (payload_len - len(b'\x00\x01') -  len(b'\x00') - len(enc_digest))
        payload += b'\x00'
        payload += enc_digest
        return payload

    
    def get_bb_signature_forgery_payload(self, message, key_size_bytes):
        """
            generates pkcs#1 encoded payload from message, padded upto key_size_bytes

            Params-
                :message - (bytearray) utf-8 encoded message to sign in bytes
                :key_size_bytes - (int) size of rsa key in bytes
        """
        return self.get_pkcs1_message(message, hashlib.sha256(), key_size_bytes)
