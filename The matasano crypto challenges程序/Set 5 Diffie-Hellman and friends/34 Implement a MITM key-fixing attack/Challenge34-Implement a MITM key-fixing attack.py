#coding:utf-8
from code import *
import random
from hashlib import sha1
p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
g = 2

def randbytes(n):
    return ''.join([chr(random.randint(0,255)) for _ in xrange(n)])

def get_a_or_b(p):
    return random.randint(1, p-1)

def intToBytes(integer):
    '''
    convert a int num to bytes string
    '''
    hex_form = hex(integer)[2:]
    if hex_form[-1]=='L':
    	hex_form=hex_form[:-1]
    if (len(hex_form) % 2):
        hex_form = '0' + hex_form
    return bytearray.fromhex(hex_form)

def secretToKeys(secret):
    hashoutput = sha1(secret).digest()
    encKey = hashoutput[0:16]
    return encKey

def mypow(a, b, c):
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

def message1():
	'''
	A->B
		Send "p", "g", "A"
	'''
	a = get_a_or_b(p-1)
	A = mypow(g, a, p)
	send = { "p" : p, 
			 "g" : g,
			 "A" : A,
			 "a" : a #a作为私钥，实际传输中不会发送，在此只为方便模拟供后续函数使用
			 } 	 
	return send

def message2(send):
	'''
	B->A
		Send "B"
	'''
	b = get_a_or_b(p-1)
	B = mypow(send['g'],b,send['p'])
	send["b"] = b #b作为私钥，实际传输中不会发送，在此只为方便模拟供后续函数使用
	send['B'] = B

	return send

def message3(send):
	'''
	A->B
		Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
	'''
	#A的共享密钥
	a_shared = mypow(send["B"], send["a"], send["p"])
	
	#设置aes_cbc_encrypt()的三个参数
	send["a_enckey"] = secretToKeys(intToBytes(a_shared))
	a_iv = randbytes(16)
	message = "Use the code you just worked out"
	
	a_ciphertext = aes_cbc_encrypt(message, send["a_enckey"],a_iv)
	send["a_ciphertext"] = a_ciphertext
	send["a_iv"] = a_iv

	return send

def message4(send):
	'''
	B->A
		Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
	'''
	#B的共享密钥
	b_shared = mypow(send["A"], send["b"], send["p"])
	#send["b_enckey"]应该与上一步中send["a_enckey"]是相同的
	send["b_enckey"] = secretToKeys(intToBytes(b_shared))
	b_iv = randbytes(16)

	received_message = aes_cbc_decrypt(send["a_ciphertext"], send["b_enckey"], send["a_iv"])
	b_ciphertext = aes_cbc_encrypt(unpad(received_message,16), send["b_enckey"], b_iv)
	send["b_ciphertext"] = b_ciphertext
	send["b_iv"] = b_iv
	send["b_received_message"] = unpad(received_message,16)
	return send

def message5(send):
    send["a_received_plain"] = unpad(aes_cbc_decrypt(send["b_ciphertext"], send["a_enckey"], send["b_iv"]),16)
    return send

def check_protocol(send):
    assert(send["a_received_plain"] == send["b_received_message"])


def message1_A_M_B(send):
	'''
	A->M
		Send "p", "g", "A"
	M->B
		Send "p", "g", "p"
	'''
	send["A"] = send["p"]
	return send

def message1_B_M_A(send):
	'''
	B->M
		Send "B"
	M->A
		Send "p"
	'''
	send["B"] = send["p"]

	return send

def message2_A_M_B(send):
	'''
	A->M
		Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
	M->B
		Relay that to B
	as same as message3()
	'''
	send = message3(send)
	return send

def message2_B_M_A(send):
	'''
	B->M
		Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
	M->A
		Relay that to A

	as same as message4()
	'''	
	
	send = message4(send)
	return send

def MITM_attack_test():
    send = message1()
    send = message1_A_M_B(send)
    send = message2(send);
    send = message1_B_M_A(send);
    send = message3(send);
    send = message2_A_M_B(send);
    send = message4(send);
    send = message2_B_M_A(send);
    send = message5(send)
    check_protocol(send)


if __name__ == '__main__':
	#首先测试无中间人介入时的正常协议过程
	a=message1()
	b=message2(a)
	c=message3(b)
	d=message4(c)
	e=message5(d)
	#一旦协议内容出错，assert将中断程序		
	check_protocol(e)
	print "No Middleman , Protocol Passed!"

	#测试中间人介入时通过如题操作，使协议仍然过程工作
	MITM_attack_test()
	print "Middleman with MITM_attack, Protocol Passed!"