#coding:utf-8
from code import *

'''
reference:http://www.freebuf.com/articles/web/15504.html

解密的时候，c0经持有真正密钥的算法解密得到中间件intermediate是唯一确定的，
中间件的最后一个字节只有唯一的某值使得它自己异或上构造的IV最后一个字节后，
得到明文信息的最后一个字节为0x01且该填充有效，通过遍历构造IV的最后一个字节的255个值，
每次将构造的特定IV和密文块输入到查询系统decryption_oracle()中查看填充是否有效，
若是有效的，则此时能够求得intermediate最后一字节=构造IV的最后一字节^0x01

依此类推，当变化IV最后两字节来得到intermediate倒数第二个字节时，需要填充为
0x02 0x02这样来使得有效通过，而intermediate最后一个字节已经通过上述操作得到，
所以此时变更构造IV的最后一个字节为0x02 ^ intermediate的最后一个字节，
然后继续遍历IV倒数第二个字节使得填充有效通过，再得到intermediate的倒数第二个字节

intermediate再往前的字节依此迭代操作下去，就可恢复整个块的intermediate，
将整块的intermediate与对应整块的密文进行异或就可得到此块明文。
对别的块依次进行如此操作即可恢复全部密文

CBC padding oracle攻击的关键有两点：
1.能获取到密文和所使用的IV
2.能够触发某个系统对输入的密文和IV进行解密，尤其是填充无效时一定会抛出异常

启示：
设计解密系统的时候，在进行异常处理时不要直接抛出类似填充无效的异常，
可以设计一个在填充无效时返回给查询者的某个消息，可以是乱码或者别的什么
假装告诉查询者填充有效并且得到了解密。

'''


#the first function
def get_target():
    IV = randbytes(16)    
    plaintext = b64decode(random.choice(choices))
    print "Target message :\n",plaintext
    print "--------------------------------------"


    ciphertext = aes_cbc_encrypt(plaintext, key, IV)
    return ciphertext, IV

#the second function
#simulate a server which received ciphertext with IV and decrtpts ciphertext and returns whether padding is valid 
def decryption_oracle(ciphertext, IV):

        try:
                plaintext = aes_cbc_decrypt(ciphertext, key, IV)
                unpadpt = unpad(plaintext, 16)
        except InvalidPaddingError as e:
                return False

        return True


key = randbytes(16)

choices = ["MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc="
                ,"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic="
                ,"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw=="
                ,"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg=="
                ,"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl"
                ,"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA=="
                ,"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw=="
                ,"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8="
                ,"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g="
                ,"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
        ]

'''
The decryption here depends on a side-channel leak by the decryption function. 
The leak is the error message that the padding is valid or not.
'''

def cbc_padding_oracle_attack():

    ciphertext, IV = get_target()

    result=""

    for block_num in range(len(ciphertext)/16):

            bytes_recovered=''
            loop_iv=''
            intermediate_value=[]
            for loop_count in xrange(15,-1,-1):

                    testiv = "A" * loop_count
                    
                    candidates = []

                    for i in xrange(0x100):
                        #print len((ciphertext[0:16], testiv + chr(i)+loop_iv))
                        if decryption_oracle(ciphertext[16*block_num:16*(block_num+1)], testiv + chr(i)+loop_iv):
                        	candidates.append(chr(i))

                    #清空已知填充iv
                    loop_iv=''

                    if len(candidates) > 1:
                            print "error!"
                            print candidates
                            exit(1)
                    else:
                        intermediate_value.append(chr(ord(candidates[0])^(16-loop_count)))
                        plaintext = chr(  ord(intermediate_value[len(intermediate_value)-1])^ord( IV[loop_count]) )
                        
                        bytes_recovered+=plaintext
                        
                        for j in range(len(intermediate_value)):
                            loop_iv += chr( (16-loop_count+1) ^ ord(intermediate_value[j]) )

                        loop_iv = loop_iv[::-1]
            
            bytes_recovered = bytes_recovered[::-1]

            print bytes_recovered
            
            result += bytes_recovered
                        
            #下一块的IV为上一块的密文
            IV = ciphertext[16*block_num:16*(block_num+1)]
 
    print "--------------------------------"
    print "Recovered message :\n",unpad(result,16)

if __name__ == '__main__':
    cbc_padding_oracle_attack()



