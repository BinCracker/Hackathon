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
		Send "p", "g"
	'''
	send = {}
	send["p"] = p
	send["g"] = g
	return send

def message2(send):
	'''
	B->A
		Send ACK
	'''	
	return send

def message3(send):
	'''
	A->B
		Send "A"
	'''
	a = get_a_or_b(p-1)
	A = mypow(g, a, p)
	send['a'] = a
	send['A'] = A
	return send

def message4(send):
	'''
	B->A
		Send "B"
	'''
	b = get_a_or_b(p-1)
	B = mypow(send['g'],b,send['p'])
	send["b"] = b 
	send['B'] = B
	return send

def message5(send):
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

def message6(send):
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
	#print "b_received_message---",send["b_received_message"]
	return send

def final(send):
	send["a_received_plain"] = unpad(aes_cbc_decrypt(send["b_ciphertext"], send["a_enckey"], send["b_iv"]),16)
	#print "a_received_plain---",send["a_received_plain"]
	return send

def check_protocol(send):
    assert(send["a_received_plain"] == send["b_received_message"])


'''
Do the MITM attack again, but play with "g". What happens with:

    g = 1
    g = p
    g = p - 1
'''

def message1_5_g1(send):
    send["g"] = 1
    return send
def message3_5_g1(send):
    send["A"] = 1
    return send



def check_protocol_g1(send):
	'''
     B public key is 1^b = 1
     A secret is (1)^a = 1
     B secret is (1)^b = 1
    '''
   	m_secret = 1
   	m_cipherkey = secretToKeys(intToBytes(m_secret))
   	m_plain_a = unpad(aes_cbc_decrypt(send["a_ciphertext"], m_cipherkey, send["a_iv"]),16)
   	m_plain_b = unpad(aes_cbc_decrypt(send["b_ciphertext"], m_cipherkey, send["b_iv"]),16)
   	assert(m_plain_a == send["a_received_plain"])
   	assert(m_plain_b == send["b_received_message"])

def run_g1():
    send = message1()
    send = message1_5_g1(send)
    send = message2(send)
    send = message3(send)
    send = message3_5_g1(send)
    send = message4(send)
    send = message5(send)
    send = message6(send)
    send = final(send)
    check_protocol(send)
    check_protocol_g1(send)

# g = p
def message1_5_gp(send):
    send["g"] = send["p"]
    return send
def message3_5_gp(send):
    send["A"] = send["p"]
    return send
def check_protocol_gp(send):

    m_secret = 0
    m_cipherkey = secretToKeys(intToBytes(m_secret))
    m_plain_a = unpad(aes_cbc_decrypt(send["a_ciphertext"], m_cipherkey, send["a_iv"]),16)
    m_plain_b = unpad(aes_cbc_decrypt(send["b_ciphertext"], m_cipherkey, send["b_iv"]),16)
    assert(m_plain_a == send["a_received_plain"])
    assert(m_plain_b == send["b_received_message"])

# check_protocol() takes care of the rest
def run_gp():
    send = message1()
    send = message1_5_gp(send)
    send = message2(send)
    send = message3(send)
    send = message3_5_gp(send)
    send = message4(send)
    send = message5(send)
    send = message6(send)
    send = final(send)
    check_protocol(send)
    check_protocol_gp(send)


# g = (p-1)
def message1_5_gp1(send):
    send["g"] = send["p"]-1
    return send
def message3_5_gp1(send):
    send["A"] = send["p"]-1
    return send
def message5_5_gp1(send):
    '''
     B's secret is (-1)^b which is either (+1) or (-1) (and also B)
     A's secret is (-1)^b^a, which is either (+1) or (-1)

    '''
    cipherkey_plus1 = secretToKeys(intToBytes(1))
    cipherkey_minus1 = secretToKeys(intToBytes(send["p"]-1))
    plain_plus1 = aes_cbc_decrypt(send["a_ciphertext"], cipherkey_plus1, send["a_iv"])
    plain_minus1 = aes_cbc_decrypt(send["a_ciphertext"], cipherkey_minus1, send["a_iv"])
    plain = None
    
    try:
        plain = unpad(plain_plus1,16)
        send["m_key_a"] = cipherkey_plus1
    except ValueError:
        plain = unpad(plain_minus1,16)
        send["m_key_a"] = cipherkey_minus1
    send["m_plain_a"] = plain
    # encrypt to B's key
    send["m_key_b"] = secretToKeys(intToBytes(send["B"]))
    send["a_cipher"] = aes_cbc_encrypt(plain, send["m_key_b"], send["a_iv"])
    return send

def message6_5_gp1(send):
    # decrypt message from B's key, encrypt to A's key
    send["m_plain_b"] = unpad(aes_cbc_decrypt(send["b_ciphertext"], send["m_key_b"], send["b_iv"]),16)
    send["b_ciphertext"] = aes_cbc_encrypt(send["m_plain_b"],send["m_key_a"], send["b_iv"])
    return send

def check_protocol_gp1(send):
    # we've already computed the plaintexts...
    assert(send["m_plain_a"] == send["a_received_plain"])
    assert(send["m_plain_b"] == send["b_received_message"])
def run_gp1():
    send = message1()
    send = message1_5_gp1(send)
    send = message2(send)
    send = message3(send)
    send = message3_5_gp1(send)
    send = message4(send)
    send = message5(send)
    send = message5_5_gp1(send)
    send = message6(send)
    send = message6_5_gp1(send)
    send = final(send)
    check_protocol(send)
    check_protocol_gp1(send)

    
    
if __name__ == "__main__":
	#三个测试，任何一个若出现协议错误程序都将中断，不会打印problem 35 success
    run_g1()
    run_gp()
    run_gp1()
    print("problem 35 success")