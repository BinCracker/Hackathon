#coding:utf-8
from code import *

UnknownPt="Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
key = randbytes(16)

def encryption_oracle(plaintext):
        global key
        return aes_ecb_encrypt(plaintext+b64decode(UnknownPt),key)

def find_blocksize():
    trial_string = "A"
    prev_length = len(encryption_oracle("A"))
    new_length = prev_length
    while (new_length == prev_length):
            trial_string += "A"
            new_length = len(encryption_oracle(trial_string))
    blocksize = new_length - prev_length
    return blocksize

def detect_useECB(blocksize=find_blocksize()):
    test_ecb = encryption_oracle("A"*2*blocksize)
    if test_ecb[0:blocksize] == test_ecb[blocksize:blocksize*2]:
        print "Using ECB : True!"
        return True
    else:
        print "Using ECB : Flase!"
        exit(1)

def break_ecb():

    '''
    比如分组块长度是16
    构造15个A串上未知内容的第1个字符组成16字节分组，经ECB加密得到目标密文target
    构造15个A然后暴力猜解第16个字节，经加密得到密文test和target比对
    只比对当前正在处理的密文块，如果值一致就表明猜解成功，得到一个字节的明文
    不断重复下去知道获得所有块的明文
    '''

    blocksize = find_blocksize()
    assert(detect_useECB())
    print "Breaking....................."
    print "--------------------------------------------------"

    bytes_recovered = ""
    loop_count=1

    while True:
        for trial_len in xrange(blocksize-1,-1,-1):
            
            trial_str = "A"*trial_len
            target = encryption_oracle(trial_str)

            for char in xrange(10,126):
                test = encryption_oracle(trial_str+bytes_recovered+chr(char))
                if test[:blocksize*loop_count] == target[:blocksize*loop_count]:
                    bytes_recovered+=chr(char)                              
                    break
        print bytes_recovered 
        print "--------------------------------------------------"

        if b64encode(bytes_recovered) == UnknownPt:
            print "Succeed to break ecb encryption!"
            break
        else:
            loop_count+=1
            
    return bytes_recovered

    
if __name__ == '__main__':
    result = break_ecb()


