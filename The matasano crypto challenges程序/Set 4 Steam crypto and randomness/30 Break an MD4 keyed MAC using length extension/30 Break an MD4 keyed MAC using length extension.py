#coding:utf-8
import md4Breaking
from array import array
from string import join
from struct import pack,unpack
#这就是方便hex编解码、char之间的转换
_DECODE = lambda x, e: list(array('B', x.decode(e)))
_ENCODE = lambda x, e: join([chr(i) for i in x], '').encode(e)
HEX_TO_BYTES = lambda x: _DECODE(x, 'hex')
TXT_TO_BYTES = lambda x: HEX_TO_BYTES(x.encode('hex'))
BYTES_TO_HEX = lambda x: _ENCODE(x, 'hex')
BYTES_TO_TXT = lambda x: BYTES_TO_HEX(x).decode('hex')

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


class myAttack:

    def __init__(self,a,b,c,d):
        #初始化状态为之前的到mac时的状态
        self.A = a
        self.B = b
        self.C = c
        self.D = d

    def myUpdate(self,with_pad):
        #得到bytes的，加上了padding的msgFinal
        msg_bytes = TXT_TO_BYTES(with_pad)
        print len(msg_bytes)
        #把得到的msgFinal划成512bit的组，分别送入myCompress，用于改变状态
        for i in range(0, len(msg_bytes), 64):
            self.myCompress(msg_bytes[i:i+64])

    def myCompress(self,block):

        a = self.A
        b = self.B
        c = self.C
        d = self.D

        #构造直接开搞的compress
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

    def myPad(self,guessKeyLen,msg,attackMsg):
        #guessKeyLen以字节计算，
        #返回len(猜的K+oldMsg+oldPadding+attackMsg)长度的消息对应的padding
        n = len(msg) + guessKeyLen + self.getOldPadLen(guessKeyLen,msg) + len(attackMsg)
        bit_len = n * 8
        index = (bit_len >> 3) & 0x3fL
        pad_len = 120 - index
        if index < 56:
            pad_len = 56 - index
        padding = '\x80' + '\x00'*63
        #这也是补位，补长度，最后加上原消息长度，也是用64位表示
        padding_msg = padding[:pad_len] + pack('<Q', bit_len)
        #返回补上了相应padding的数据（char型
        print 'new pad--->'+padding_msg.encode('hex')
        return padding_msg

    def getOldPadLen(self,guessKeyLen,msg):
        #print guessKeyLen
        #print msg
        n = len(msg) + guessKeyLen
        bit_len = n * 8
        index = (bit_len >> 3) & 0x3fL
        pad_len = 120 - index
        if index < 56:
            pad_len = 56 - index
        padding = '\x80' + '\x00'*63
        #这也是补位，补长度，最后加上原消息长度，也是用64位表示
        padding_msg = padding[:pad_len] + pack('<Q', bit_len)
        #返回（char型）长度
        print 'oldpad--(应该与正规的pad一样)->'+padding_msg.encode('hex')
        return len(padding_msg)

    def myDigist(self):
        return BYTES_TO_HEX(TXT_TO_BYTES(pack('<IIII', self.A, self.B, self.C, self.D)))



msg = 'Break an MD4 keyed MAC'
attackMsg = ' using length extension'

md = md4Breaking.MD4()
md.update(msg)
print md.digest()
#正常计算之前的mac，把状态给弄出来，后面用到（相当于sha-1里面把mac分成32bit的）
print '算完mac的当前状态：',md.A,md.B,md.C,md.D

#状态设置为得到的状态
attack = myAttack(md.A,md.B,md.C,md.D)



def _pad(msg):
    #稍微改造一下，把得到的padding也返回一下，方便检查
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
    return (padded_msg,padding[:pad_len] + pack('<Q', bit_len))


#这里计算出来的是待会儿用来验证扩展后计算出来的到底对不对
md1 = md4Breaking.MD4()
tmpmsg = md1.K + msg
tmpmsg,padding = _pad(tmpmsg)
print '原来正规的pad--->'+padding.encode('hex')
md1.update(msg+padding+attackMsg)
Ineed = md1.digest()



#构造扩展的部分，不知道具体是啥的秘钥是12位，实际中可能要猜测一下长度
##注意，前面已经将状态设置为得到之前mac时的状态
##attack = myAttack(md.A,md.B,md.C,md.D)
##那么直接送进去“轮”从这个状态开始继续进行计算
attackMsgtest = attackMsg + attack.myPad(12,msg,attackMsg)
#送进去改变状态
attack.myUpdate(attackMsgtest)
#得到结果
print '猜测秘钥长度为12的时候扩展攻击得到的：\n'+attack.myDigist()
print 'originalMsg+originalPadding+newMessage送入正规keyed md4得到的：\n'+Ineed
print '两者一致，success...'
