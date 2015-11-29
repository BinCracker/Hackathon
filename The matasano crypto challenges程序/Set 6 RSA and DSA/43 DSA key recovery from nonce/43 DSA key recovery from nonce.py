#coding:utf-8


p = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1

q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b

g = 0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291

y = 0x84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17

msg_hash = 0xd2d0714f014a9784047eaeccf956520045c45265

r = 548099063082341131477253921760299949438196259240

s = 857042759984254168557880549501802188789837994940

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

def egcd(a, b):
    if b == 0:
        return (1, 0)
    else:
        q = a // b
        r = a % b
        (s, t) = egcd(b, r)
        return (t, s - q * t)

# Returns a^-1 mod N
def invmod(a, N):
    
    (x, y) = egcd(a, N)
    return x % N


'''
DSA参数算法描述：

p：L bits长的素数。L是64的倍数，范围是512到1024；
q：p - 1的160bits的素因子；
g：g = h^((p-1)/q) mod p，h满足h < p - 1, h^((p-1)/q) mod p > 1；
x：x < q，x为私钥 ；
y：y = g^x mod p ，( p, q, g, y )为公钥；
H( x )：One-Way Hash函数。DSS中选用SHA( Secure Hash Algorithm )。
p, q, g可由一组用户共享，但在实际应用中，使用公共模数可能会带来一定的威胁。签名及验证协议如下：
1. P产生随机数k，k < q；
2. P计算 r = ( g^k mod p ) mod q
s = ( k^(-1) (H(m) + xr)) mod q
签名结果是( m, r, s )。

3. 验证时计算 w = s^(-1)mod q
u1 = ( H( m ) * w ) mod q
u2 = ( r * w ) mod q
v = (( g^u1 * y^u2 ) mod p ) mod q
若v = r，则认为签名有效。

'''

def get_dsa_key_from_known_k(r, s, k, msg_hash, q=q):
	'''
	x is private key
	      (s * k) - H(msg)
	  x = ----------------  mod q
	              r
	'''

	top = ((s*k) - msg_hash) % q
	x = top * invmod(r, q)
	return x

def recover_dsa_key():
	'''
	y is public key

	y：y = g^x mod p 
	'''

	for k in range(65537):
	    potential_x = get_dsa_key_from_known_k(r, s, k, msg_hash)	    
	    if (mypow(g, potential_x, p) == y):
	        return (potential_x, k)	
	raise Exception

if __name__ == "__main__":
    print("(private key x, DSA key k): ", recover_dsa_key())
    print("problem 43 success")