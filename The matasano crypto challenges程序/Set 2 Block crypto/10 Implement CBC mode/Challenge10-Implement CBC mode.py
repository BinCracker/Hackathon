from code import *

if __name__ == '__main__':
    
    f = open('Challenge10.txt','r').readlines()
    ciphertext=''.join([x.strip() for x in f])
    ciphertext = b64decode(ciphertext)

    key = "YELLOW SUBMARINE" 
    iv='\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    _plaintext = AES.new(key,AES.MODE_CBC,iv).decrypt(ciphertext)
    plaintext = aes_cbc_decrypt(ciphertext,key,iv)

    if plaintext==_plaintext:
        print "succeed!"
        print plaintext