#coding:utf-8
p = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1
q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
g = 0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291

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

'------------------------------------------------------------'

g0 = 0

def do_dsa_g0(message_hash):
	'''
	g=g0=0时按算法计算公钥
	'''
	x = 8675309
	k = 24601
	y = mypow(g0, x, p)
	r = mypow(g0, k, p) % q
	s = (invmod(k, p) * (message_hash + x*r)) % q
	return (y,r,s)

def validate_dsa_g0(y, r, s, message_hash):
	'''
	3. 验证时计算 w = s^(-1)mod q
	u1 = ( H( m ) * w ) mod q
	u2 = ( r * w ) mod q
	v = (( g^u1 * y^u2 ) mod p ) mod q
	若v = r，则认为签名有效。
	'''
	w = invmod(s, q)
	u1 = (message_hash * w) % q;
	u2 = (r*w) % q;
	v = (mypow(g0, u1, p) * mypow(y, u2, p) % p) % q
	return v == r

def demo_dsa_g0():
	'''
	g0=0时测试
	任何改变若不通过则中断
	'''
	message_hash = 0x0102030405060708091011121314151617181920
	(y, r, s) = do_dsa_g0(message_hash)
	assert(r == 0)
	assert(validate_dsa_g0(y, r, s, message_hash))
	# 随便改变公钥部分
	assert(validate_dsa_g0(13, 0, 23423423432, message_hash))
	# 随便改变哈希部分
	assert(validate_dsa_g0(32432423, 0, 342423432423, 0x3daf05ce546d1))

'------------------------------------------------------------'

'''
Now, try (p+1) as "g". With this "g", you can generate a magic signature s, r for any DSA public key that will validate against any string. For arbitrary z:

  r = ((y**z) % p) % q

        r
  s =  --- % q
        z
'''

g1_x = 985316
g1_y = mypow(g, g1_x, p) # key generation uses legit params
g1 = (p + 1)
g1_r = g1_y %  q # set z to 1
gr_s = g1_r # set z to 1

def validate_dsa_g1(y, r, s, message_hash):
    w = invmod(s, q)
    u1 = (message_hash * w) % q
    u2 = (r*w) % q
    v = (mypow(g1, u1, p) * mypow(y, u2, p) % p) % q
    return v == r

def demo_dsa_g1():
    hash1 = 0xe02aa1b106d5c7c6a98def2b13005d5b84fd8dc8 #sha1(b'Hello, world')
    hash2 = 0xdc519a4510e5e848e1f77da409fa1410c84d43fb #sha1(b'Goodbye, world')
    #测试signature s, r for any DSA public key that will validate against any string.
    assert(validate_dsa_g1(g1_r, g1_r, gr_s, hash1))
    assert(validate_dsa_g1(g1_r, g1_r, gr_s, hash2))


if __name__ == "__main__":
	#对两次改变g进行测试，任何一个不通过将中断不会打印"Problem 45 success"
    demo_dsa_g0()
    demo_dsa_g1()
    print("Problem 45 success")
