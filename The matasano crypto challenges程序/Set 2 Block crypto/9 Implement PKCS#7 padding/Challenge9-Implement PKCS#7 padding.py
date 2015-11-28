from code import *

	
if __name__ == '__main__':	
	if pkcs7_padding("YELLOW SUBMARINE", 20) == "YELLOW SUBMARINE\x04\x04\x04\x04":
		print "padding succeed!"


	