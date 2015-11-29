#coding:utf-8
from array import array
from string import join
from struct import pack, unpack


#这就是方便hex编解码、char之间的转换
_DECODE = lambda x, e: list(array('B', x.decode(e)))
_ENCODE = lambda x, e: join([chr(i) for i in x], '').encode(e)
HEX_TO_BYTES = lambda x: _DECODE(x, 'hex')
TXT_TO_BYTES = lambda x: HEX_TO_BYTES(x.encode('hex'))
BYTES_TO_HEX = lambda x: _ENCODE(x, 'hex')
BYTES_TO_TXT = lambda x: BYTES_TO_HEX(x).decode('hex')

#得到msg相应的填充后的数据（按字符对待）
def _pad(msg):
    #获取消息字节数、bit数
	n = len(msg)
	bit_len = n * 8
	index = (bit_len >> 3) & 0x3fL
	pad_len = 120 - index
	if index < 56:
		pad_len = 56 - index
	padding = '\x80' + '\x00'*63
	#这也是补位，补长度，最后加上原消息长度，也是64位表示
	padded_msg = msg + padding[:pad_len] + pack('<Q', bit_len)
	#返回补上了相应padding的数据（char型）
	return padded_msg

#循环左移
def _left_rotate(n, b):
	return ((n << b) | ((n & 0xffffffff) >> (32 - b))) & 0xffffffff


#定义了一些运算，用于“轮”中
def _f(x, y, z): return x & y | ~x & z
def _g(x, y, z): return x & y | x & z | y & z
def _h(x, y, z): return x ^ y ^ z

def _f1(a, b, c, d, k, s, X): return _left_rotate(a + _f(b, c, d) + X[k], s)
def _f2(a, b, c, d, k, s, X): return _left_rotate(a + _g(b, c, d) + X[k] + 0x5a827999, s)
def _f3(a, b, c, d, k, s, X): return _left_rotate(a + _h(b, c, d) + X[k] + 0x6ed9eba1, s)

class MD4:

    def __init__(self):
        #初始“状态”
        self.A = 0x67452301
        self.B = 0xefcdab89
        self.C = 0x98badcfe
        self.D = 0x10325476
        self.K = 'This Is Key!'

    def update(self, message_string):
        #得到bytes的，加上了padding的msgFinal
		msg_bytes = TXT_TO_BYTES(_pad(self.K+message_string))
        #把得到的msgFinal划成512bit的组，分别送入_compress，用于改变状态
		for i in range(0, len(msg_bytes), 64):
			self._compress(msg_bytes[i:i+64])

    def _compress(self, block):
        #这个就是每轮运算的细节，每次送入一个512bit的块，运算后“状态”会改变
		a, b, c, d = self.A, self.B, self.C, self.D

		x = []
		for i in range(0, 64, 4):
			x.append(unpack('<I', BYTES_TO_TXT(block[i:i+4]))[0])

		a = _f1(a,b,c,d, 0, 3, x)
		d = _f1(d,a,b,c, 1, 7, x)
		c = _f1(c,d,a,b, 2,11, x)
		b = _f1(b,c,d,a, 3,19, x)
		a = _f1(a,b,c,d, 4, 3, x)
		d = _f1(d,a,b,c, 5, 7, x)
		c = _f1(c,d,a,b, 6,11, x)
		b = _f1(b,c,d,a, 7,19, x)
		a = _f1(a,b,c,d, 8, 3, x)
		d = _f1(d,a,b,c, 9, 7, x)
		c = _f1(c,d,a,b,10,11, x)
		b = _f1(b,c,d,a,11,19, x)
		a = _f1(a,b,c,d,12, 3, x)
		d = _f1(d,a,b,c,13, 7, x)
		c = _f1(c,d,a,b,14,11, x)
		b = _f1(b,c,d,a,15,19, x)

		a = _f2(a,b,c,d, 0, 3, x)
		d = _f2(d,a,b,c, 4, 5, x)
		c = _f2(c,d,a,b, 8, 9, x)
		b = _f2(b,c,d,a,12,13, x)
		a = _f2(a,b,c,d, 1, 3, x)
		d = _f2(d,a,b,c, 5, 5, x)
		c = _f2(c,d,a,b, 9, 9, x)
		b = _f2(b,c,d,a,13,13, x)
		a = _f2(a,b,c,d, 2, 3, x)
		d = _f2(d,a,b,c, 6, 5, x)
		c = _f2(c,d,a,b,10, 9, x)
		b = _f2(b,c,d,a,14,13, x)
		a = _f2(a,b,c,d, 3, 3, x)
		d = _f2(d,a,b,c, 7, 5, x)
		c = _f2(c,d,a,b,11, 9, x)
		b = _f2(b,c,d,a,15,13, x)

		a = _f3(a,b,c,d, 0, 3, x)
		d = _f3(d,a,b,c, 8, 9, x)
		c = _f3(c,d,a,b, 4,11, x)
		b = _f3(b,c,d,a,12,15, x)
		a = _f3(a,b,c,d, 2, 3, x)
		d = _f3(d,a,b,c,10, 9, x)
		c = _f3(c,d,a,b, 6,11, x)
		b = _f3(b,c,d,a,14,15, x)
		a = _f3(a,b,c,d, 1, 3, x)
		d = _f3(d,a,b,c, 9, 9, x)
		c = _f3(c,d,a,b, 5,11, x)
		b = _f3(b,c,d,a,13,15, x)
		a = _f3(a,b,c,d, 3, 3, x)
		d = _f3(d,a,b,c,11, 9, x)
		c = _f3(c,d,a,b, 7,11, x)
		b = _f3(b,c,d,a,15,15, x)

		# 状态更新
		self.A = (self.A + a) & 0xffffffff
		self.B = (self.B + b) & 0xffffffff
		self.C = (self.C + c) & 0xffffffff
		self.D = (self.D + d) & 0xffffffff

    def digest(self):
        #得到md4处理之后的数据(bytes型)
		return BYTES_TO_HEX(TXT_TO_BYTES(pack('<IIII', self.A, self.B, self.C, self.D)))


