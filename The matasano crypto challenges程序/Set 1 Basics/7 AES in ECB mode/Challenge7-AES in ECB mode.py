from code import *
from Crypto.Cipher import AES

key = "YELLOW SUBMARINE"


if __name__ == '__main__':
	
	f = open('Challenge7.txt','r')
	ciphertext=''.join([x.strip() for x in f])#drops space 
	ciphertext = b64decode(ciphertext)

	_plaintext = AES.new(key, AES.MODE_ECB).decrypt(ciphertext)
	plaintext = aes_ecb_decrypt(ciphertext,key)

	if plaintext == _plaintext:
		print "Succeed!"
		print plaintext

