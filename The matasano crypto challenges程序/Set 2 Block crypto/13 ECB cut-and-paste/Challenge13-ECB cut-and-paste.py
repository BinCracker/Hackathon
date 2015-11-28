#coding:utf-8
from code import *

class Profile:
    def __init__(self,email=None,uid=10, role='user'):
        self.email = email
        self.uid = uid
        self.role = role

    def encode(self):
        return "email=%s&uid=%d&role=%s" % (self.email, self.uid, self.role)

    def decode(self, encoded):
        params = encoded.split("&")
        self.email = params[0].split("=")[1]
        self.uid = int(params[1].split("=")[1])
        self.role = params[2].split("=")[1]

    def dump(self):
        return "{\n\temail: '%s'\n\tuid: %d\n\trole: '%s'\n}" % (self.email, self.uid, self.role)


def profile_for(email_address):
        addr = email_address.replace("&",'').replace("=",'')
        return Profile(addr, 10, "user").encode()



def encryption_oracle(email_address):
        
        return aes_ecb_encrypt(profile_for(email_address), key)

def decryption_oracle(ciphertext):

        encoding = aes_ecb_decrypt(ciphertext, key)

        P = Profile()
        P.decode(encoding)

        return P.dump()



if __name__ == '__main__':
    key = randbytes(24)

    #核心做法就是构造两次查询，对特定的密文块进行切分挑选再重组为一个密文

    #构造输入使得得到开头就含admin的第三个密文块
    construct_email="A"*(16 - len("email=")) + "admin" 
    third_block = encryption_oracle(construct_email)[16:32]
    print aes_ecb_decrypt(third_block,key)


    #构造前两个密文块，使email=某内容为16字节一整块，并加上正常的中间一块
    construct_email="A"*(16-len("email="))+"B"*(16-len('&uid=10&role='))
    #construct_email="666666@qq.com"
    #construct_email的内容可以随意写，但不能超过13字节长，否则会导致解码使匹配不到uid
    firstSecoond_block = encryption_oracle(construct_email)[0:32]
    print aes_ecb_decrypt(firstSecoond_block,key)


    print aes_ecb_decrypt(firstSecoond_block+third_block, key)
    print decryption_oracle(firstSecoond_block+third_block)

