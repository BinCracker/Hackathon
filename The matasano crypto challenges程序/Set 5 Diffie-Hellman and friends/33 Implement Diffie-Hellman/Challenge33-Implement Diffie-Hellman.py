#!/usr/bin/python2
#coding:utf-8
import random
from hashlib import sha256

def get_a_or_b(p):
    return random.randint(1, p-1)

def intToBytes(integer):
    '''
    convert a int num to bytes string
    '''
    hex_form = hex(integer)[2:]
    if (len(hex_form) % 2):
        hex_form = '0' + hex_form
    return bytearray.fromhex(hex_form)

def secretToKeys(secret):
    hashoutput = sha256(secret).digest()
    encKey = hashoutput[0:16]
    macKey = hashoutput[16:32]
    return encKey, macKey

def smallNumDH():
    p = 37
    g = 5
    #生成私钥a,b
    a = get_a_or_b(p)
    b = get_a_or_b(p)
    #生成各自公钥    
    A = pow(g,a,p)
    B = pow(g,b,p)
    #计算共享密钥，若双方不一致则中断
    s_b = pow(B,a,p)
    s_a = pow(A,b,p)
    assert(s_a == s_b)
    return secretToKeys(intToBytes(s_a))

def Mypow(a, b, c):
    '''
    args:
        a,b,b: a int num
    function:
        To compute (a^b)mod c , and returns its value
    '''

    if (b == 0):
        return 1
    if (b == 1):
        return (a % c)

    b_bits = bin(b)[2:]
    res = a
    for i in range(1, len(b_bits)):    
        res = res * res        
        if (b_bits[i] == '1' ):
            res = res * a        
        res = res % c
        
    return res

def testMypow():
    test_b = [0, 1, 5, 65537, pow(2,32)-1, pow(2,32) + 1, pow(2,256) + pow(2,64) + pow(2,16) + 1]
    
    #通过test_b中一系列大数来测试Mypow(),一旦与系统库中pow()计算结果不同就中断
    for b in test_b:
        theirs = pow(g, b, p)
        mine = Mypow(g, b, p)        
        assert(mine == theirs)
    print "Mypow() Passed!"


if __name__ == '__main__':
    p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
    g = 2
    smallNumDH()
    testMypow()


