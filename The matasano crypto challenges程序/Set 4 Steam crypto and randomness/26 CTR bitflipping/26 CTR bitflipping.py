#!/usr/bin/env python3
from ssl import RAND_bytes
from Crypto.Cipher import AES
from struct import unpack, pack
def generateAESKey():
    return RAND_bytes(16);
def chunks(array, n):
    return [array[i:i+n] for i in range(0, len(array), n)]
def raw_xor(in1, in2):
    length = min(len(in1), len(in2));
    result = [(in1[i] ^ in2[i]).to_bytes(1, byteorder='big') for i in range(length)];
    return b''.join(result);
def aes_ctr(rawInput, rawKey, rawIV):
    inputBlocks = chunks(rawInput, 16);
    rawOutput = b'';
    for block in inputBlocks:
        keyStream = aes_ecb_enc(rawIV, rawKey);
        rawOutput += raw_xor(keyStream, block);
        rawIV = incrementIV(rawIV);
    return rawOutput;
def aes_ecb_enc(rawCipher, rawKey):
    aes = AES.new(rawKey, AES.MODE_ECB); 
    return aes.encrypt(rawCipher);

def incrementIV(rawIV):
    nonce = rawIV[0:8];
    LEcounter = rawIV[8:16];
    counter = unpack('<Q', LEcounter)[0];
    counter += 1;
    counter = (counter % 0x10000000000000000);
    LEcounter = pack('<Q', counter);
    return (nonce + LEcounter);
####################################################   预定义部分  ############################################
global_aes_key = generateAESKey();
global_iv = b'\x00' * 16;

prefix = b'comment1=cooking%20MCs;userdata='
suffix = b';comment2=%20like%20a%20pound%20of%20bacon'
#使用AES 的 CTR模式加密字符串
def encryptString(s):
    s = s.replace(b';', b'\';\'').replace(b'=', b'\'=\'');
    rawInput = prefix + s + suffix;
    rawOutput = aes_ctr(rawInput, global_aes_key, global_iv);
    return rawOutput;
#检测是否存在字符串";admin=true;"
def decryptAndCheckAdmin(cip):
    rawPlain = aes_ctr(cip, global_aes_key, global_iv);
    strPlain = str(rawPlain).rstrip("b'");
    if ";admin=true;" in strPlain:
        return True;
    return False;

# 进行攻击,先用全零字节填充目标字节的长度,然后加密,这样密钥流和0异或之后,我们就得到了
# 密钥流在我们想更改的位置的值
# 得到密钥流之后再和我们想更改的内容xor运算,然后加在密文里
def generateEncryptedAdminProfile():
    desiredComment = b';admin=true;';
    firstComment = b'\x00' * len(desiredComment);
    firstEncProfile = encryptString(firstComment);
    offset = len(prefix);
    firstCipher = firstEncProfile[offset:offset+len(firstComment)];
    newEncProfile = firstEncProfile[0:len(prefix)] + raw_xor(firstCipher, desiredComment) + firstEncProfile[len(prefix)+len(desiredComment):];
    return newEncProfile;
 
if __name__ == "__main__":
    if (decryptAndCheckAdmin(encryptString(b';admin=true;'))):
        raise Exception("padding quote failure");
    cip = generateEncryptedAdminProfile();
    if (decryptAndCheckAdmin(cip)):
        print("Problem 26 success");
    else:
        raise Exception("Generate admin faulre");