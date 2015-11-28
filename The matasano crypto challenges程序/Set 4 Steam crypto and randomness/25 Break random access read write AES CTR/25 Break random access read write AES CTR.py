#!/usr/bin/python2
#coding:utf-8
from code import *
key='\x01'*16
plain='hello_myworld'
nonce=0
new='test'
#原始的加密方式
def edit_encrypt(ct,key,offset,new):
    global nonce
    pt=aes_ctr_encrypt(ct, key, nonce)
    new_pt=pt[0:offset]+new+pt[offset+len(new):]
    new_ct=aes_ctr_encrypt(new_pt, key, nonce)
    return new_ct

def edit(ct,offset,new):#攻击者获得的方式
    return edit_encrypt(ct,key,offset,new)


cipher=aes_ctr_encrypt(plain,key,nonce)
new_ct=edit_encrypt(cipher,key,3,new)#攻击者可以获得的密文

#攻击者构造edit(密文，0，密文一样长度的0串)
new_pt=edit(new_ct,0,'\x00'*len(new_ct))
#得到0串进行AES加密的结果 0^key

#将密文与我们构造得到的结果异或得到明文
new_p=[]
for i in range(len(new_pt)):
        new_p+=chr(ord(new_pt[i])^ord(new_ct[i]))

#输出明文
print new_p
