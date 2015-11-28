#coding:utf-8
from code import *

key = randbytes(16)
IV = randbytes(16)

def encryption_oracle(arbitrary_inputPT):
        sanitized = arbitrary_inputPT.replace(";","%%3b").replace("=", "%%3d")
        return aes_cbc_encrypt("comment1=cooking%%20MCs;userdata=%s;comment2=%%20like%%20a%%20pound%%20of%%20bacon"%sanitized, key, IV)

def decryption_oracle(ciphertext):

        try:
                plaintext = aes_cbc_decrypt(ciphertext, key, IV).index(";admin=true;")
        except:
                return False

        return True
                             
if __name__ == '__main__':
    
    #用户数据从第三个分组开始，需要对第二个分组的密文cut进行修改
    ciphertext = encryption_oracle("A" * 32)
    cut = ciphertext[16:32]
    paste = xor_strings(xor_strings("FUck;admin=true;", "A" * 16,"ASCII"), cut,"ASCII")
    
    print decryption_oracle(ciphertext[0:16] + paste + ciphertext[32:])

    print aes_cbc_decrypt(ciphertext[0:16] + paste + ciphertext[32:], key, IV)
