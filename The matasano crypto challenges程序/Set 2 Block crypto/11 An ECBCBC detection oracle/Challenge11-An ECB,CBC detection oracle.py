from code import *

def encryption_oracle(plaintext):
	key = randbytes(16)
	plaintext = randbytes(random.randint(5, 10)) + plaintext + randbytes(random.randint(5, 10))
	if random.randint(0, 1) == 1:
		print "actually doing ECB"
		result = aes_ecb_encrypt(plaintext, key)
		global Real_ECB_Count
		Real_ECB_Count+=1
		
	else:
		print "actually doing CBC"
		iv = randbytes(16)
		result = aes_cbc_encrypt(plaintext, key,iv)
		global Real_CBC_Count
		Real_CBC_Count+=1
		
	return result


if __name__ == '__main__':
	Real_ECB_Count=0
	Real_CBC_Count=0
	Orac_ECB_Count=0
	Orac_CBC_Count=0

	for i in xrange(100):
		print "No.%d"%i
		test = encryption_oracle("X" * 50)		
		if test[16:32] == test[32:48]:
			print "Encrypting in ECB"
			Orac_ECB_Count+=1
		else:
			print "Encrypting in CBC"
			Orac_CBC_Count+=1
		print "----------------------------------"

	
	print"Error of oracling ECB:%d"%abs(Orac_ECB_Count-Real_ECB_Count)
	print"Error of oracling CBC:%d"%abs(Orac_CBC_Count-Real_CBC_Count)
	