#coding:utf-8
#运行环境：python2.7
import struct
import hashlib 
#验证实现的sha1没有问题

def _left_rotate(n, b):
	#后面用到
    return ((n << b) | (n >> (32 - b))) & 0xffffffff
    
def sha1_with_hex_return(message):
    """
    SHA-1 Hashing Function
    A hex SHA-1 digest of the input message.
    """
    #固定常量
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0
    
    #确定位数和字节数:
    original_byte_len = len(message)
    original_bit_len = original_byte_len * 8
    #添加‘1’到数据后面
    message += b'\x80'
    
    # 继续补0补到除512余数为448
    message += b'\x00' * ((56 - (original_byte_len + 1) % 64) % 64)
    
    # 用64bit表示原始消息长度，补到最后面
    message += struct.pack('>Q', original_bit_len)
    # 搞成512bit的分组
    for i in range(0, len(message), 64):
        w = [0] * 80
        # break chunk into sixteen 32-bit big-endian words w[i]
        for j in range(16):
            w[j] = struct.unpack('>I', message[i + j*4:i + j*4 + 4])[0]
        # Extend the sixteen 32-bit words into eighty 32-bit words:
        for j in range(16, 80):
            w[j] = _left_rotate(w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16], 1)
    
        # Initialize hash value for this chunk:
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4
    
        for i in range(80):
            if 0 <= i <= 19:
                # Use alternative 1 for f from FIPS PB 180-1 to avoid ~
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
    
        # sAdd this chunk's hash to result so far:
        h0 = (h0 + a) & 0xffffffff
        h1 = (h1 + b) & 0xffffffff 
        h2 = (h2 + c) & 0xffffffff
        h3 = (h3 + d) & 0xffffffff
        h4 = (h4 + e) & 0xffffffff
    
    # Produce the final hash value (big-endian):
    return '%08x%08x%08x%08x%08x' % (h0, h1, h2, h3, h4)


def dumbHashAuth(key, message):
    #加入key
    return sha1_with_hex_return(key + message);
    

def testDumHashAuth():
	#测试“碰撞”
    key = b'thisisjustatest!'
    message1 = b'test1test1test1test1';
    message2 = b'test2test2test2test2';
    #相同的key不同的msg
    tag1 = dumbHashAuth(key, message1);
    tag2 = dumbHashAuth(key, message2);
    if (tag1 == tag2):
        print("Problem 28 failure");
        return False;
    #相同的msg不同的key(此处为空key)
    forgedTag = dumbHashAuth(b'', message1);
    if (tag1 == forgedTag):
        print("Problem 28 failure");
        return False;
    print("Problem 28 success");
    return True;

if __name__ == "__main__":
    #当然得先验证一下这个函数的实现本身有没有问题
    if (hashlib.sha1(b'YELLOW SUBMARINE').hexdigest() != sha1_with_hex_return(b'YELLOW SUBMARINE')):
        print("sha1 failure");
    testDumHashAuth();
