#/usr/bin/python2
#coding:utf-8

import struct
from prob28 import dumbHashAuth
import binascii

def hexToRaw(hx):
    raw = binascii.unhexlify(hx);
    return raw;

def _left_rotate(n, b):
    return ((n << b) | (n >> (32 - b))) & 0xffffffff


#因为是恶意填充好的，直接按照512bit划开，h0~h3为寄存器状态,然后送入"各种轮"
#后面扩展攻击的时候，前面输出的mac按照160bit分为32bit每组，
#依次作为内部状态送入，相当于拼起来了，所以叫做扩展长度攻击
def nopaddingSHA(message, h0=0x67452301, h1=0xEFCDAB89, h2=0x98BADCFE, h3=0x10325476, h4=0xC3D2E1F0):

    for i in range(0, len(message), 64):
        w = [0] * 80
        for j in range(16):
            w[j] = struct.unpack('>I', message[i + j*4:i + j*4 + 4])[0]
        for j in range(16, 80):
            w[j] = _left_rotate(w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16], 1)
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4
    
        for i in range(80):
            if 0 <= i <= 19:
                f = d ^ (b & (c ^ d))
                k = 0x5A827999
            elif 20 <= i <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= i <= 59:
                f = (b & c) | (b & d) | (c & d) 
                k = 0x8F1BBCDC
            elif 60 <= i <= 79:
                f = b ^ c ^ d
                k = 0xCA62C1D6
    
            a, b, c, d, e = ((_left_rotate(a, 5) + f + e + k + w[i]) & 0xffffffff, 
                            a, _left_rotate(b, 30), c, d)
    
        h0 = (h0 + a) & 0xffffffff
        h1 = (h1 + b) & 0xffffffff 
        h2 = (h2 + c) & 0xffffffff
        h3 = (h3 + d) & 0xffffffff
        h4 = (h4 + e) & 0xffffffff
    
    # 返回16进制的mac数据
    return '%08x%08x%08x%08x%08x' % (h0, h1, h2, h3, h4)


#根据数据长度计算出填充的数据
#补位、补长度、和末尾64bit的指示数据长度的填充
#用来计算新老data的填充
def generateSHAPadding(message_length_in_bytes):
    return b'\x80' + (b'\x00' * ((56 - (message_length_in_bytes + 1) % 64) % 64)) + struct.pack('>Q', message_length_in_bytes*8)

#检测填充搞出来的新消息的mac对不对
def checkDumbHashAuth(message, tag):
    return (dumbHashAuth(hash_secret, message) == tag)

#把原来的数据扩展成新的数据
#originaldata+oldpadding+message+newpadding，其中message就是想要恶意加入的
#新填充是把前面的原始数据+原始填充+mac作为新数据的data计算来的
def appendMessage(original, tag, extra):    
    #这里因为只是消息是知道的，但是key不知道，所以不知道送进sha1的data具体长度是多少
    #那是不是没办法计算填充了？是的，但是可以猜...
    #假设key长度8个字节以内
    #依次进行猜测就行
    for i in range(65):
        oldpadding = generateSHAPadding(len(original)+i);
        newpadding= generateSHAPadding(len(original) + len(oldpadding) + len(extra) + i);
        newdata = extra + newpadding;
        tmp = tag
        #print tmp
        a = int(tmp[0:8],16)
        b = int(tmp[8:16],16)
        c = int(tmp[16:24],16)
        d = int(tmp[24:32],16)
        e = int(tmp[32:40],16)       
        newtag = nopaddingSHA(newdata, h0=a, h1=b, h2=c, h3=d, h4=e)
        if (checkDumbHashAuth(original + oldpadding + extra, newtag)):
            #如果tag对了，自然返回tag
            return newtag
    print("Failure");


hash_secret = b'YELLOW SUBMARINE'
def test29():
    #这个message就相当于original data
    message = b'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'
    #原始tag
    tag = dumbHashAuth(hash_secret, message)
    #新的tag运算，前面已经说过，最后的extra参数对应恶意加入的信息
    newtag = appendMessage(message, tag, b';admin=true');
    print("new tag = ", newtag)
    print("Problem 29 success")

if (__name__ == "__main__"):
    test29();




