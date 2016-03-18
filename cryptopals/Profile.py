import sys
from Crypto.Cipher import AES
from Crypto import Random
import base


class Profile(object):


	def __repr__(self):
		return (str(vars(self)))

	def encode(self):
		return "email=" + self.email + "&uid=" + str(self.uid) + "&role=" + self.role

def sanitize(email):
	new_email = email.replace('&','')
	new_email = new_email.replace('=','')
	return new_email

def parse(cookie):
	try:
		kvpairs = cookie.split('&')
		p = Profile()
		for kv in kvpairs:
			if '=' in kv:
				#print "kv:" , kv
				key,value = kv.split('=')
				setattr(p,key,value)
	except:
		return None

	return p

def profile_for(email):
	p = Profile()
	p.email = sanitize(email)
	p.uid = 10
	p.role = 'user'
	return p

key = Random.get_random_bytes(16)
def encrypt(plaintext):
	padded_pt = base.pkcs7_pad(plaintext,16)
	encryptor = AES.new(key,AES.MODE_ECB)
	return encryptor.encrypt(padded_pt)

def decrypt(ciphertext):
	decryptor = AES.new(key,AES.MODE_ECB)
	padded_pt = decryptor.decrypt(ciphertext)
	return padded_pt

