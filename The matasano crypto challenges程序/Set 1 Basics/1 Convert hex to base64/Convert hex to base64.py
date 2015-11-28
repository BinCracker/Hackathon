#!/usr/bin/python2
from code import *

string = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
target = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'

if __name__ == '__main__':
	if b64encode(string.decode("hex"))==target:
		print "Convert hex to base64 Succeed!"
		print target




