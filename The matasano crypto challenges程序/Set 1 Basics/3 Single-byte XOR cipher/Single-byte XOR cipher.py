#!/usr/bin/python2
from code import *

ciphertext = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
ciphertext = ciphertext.decode('hex')

if __name__ == '__main__':
	FindSingleCharXOR(6,ciphertext)

