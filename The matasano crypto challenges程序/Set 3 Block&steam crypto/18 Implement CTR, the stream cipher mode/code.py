#coding:utf-8
import random
from Crypto.Cipher import AES
from Crypto.Util import Counter

#base64加密
def b64encode(s):
    '''
    args:
            s:a string ASCII-encoded
    ''' 
    table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    assert len(table) == 64
    ret = ""
    for i in range(0, len(s), 3):
            if i + 2 < len(s):
                    chunk = (ord(s[i]) << 16) | (ord(s[i+1]) << 8) | (ord(s[i+2]))
                    ret += table[chunk >> 18] + table[(chunk >> 12) & 0x3f] + table[(chunk >> 6) & 0x3f] + table[chunk & 0x3f]
            elif i + 1 < len(s):
                    chunk = (ord(s[i]) << 16) | (ord(s[i+1]) << 8)
                    ret += table[chunk >> 18] + table[(chunk >> 12) & 0x3f] + table[(chunk >> 6) & 0x3f] + "="
            else:
                    chunk = (ord(s[i]) << 16)
                    ret += table[chunk >> 18] + table[(chunk >> 12) & 0x3f] + "=="

    return ret

#base64 解密
def b64decode(s):
    '''
    args:
            s:a string base64-encoded
    '''
    table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    assert len(table) == 64
    assert len(s) % 4 == 0

    ret = ""
    for i in range(0, len(s) - 4, 4):
            chunk = (table.index(s[i]) << 18) | (table.index(s[i+1]) << 12) | (table.index(s[i+2]) << 6) | table.index(s[i+3])
            ret += chr(chunk >> 16) + chr((chunk >> 8) & 0xff) + chr(chunk & 0xff)

    if s[-2:] == "==":
            chunk = (table.index(s[-4]) << 18) | (table.index(s[-3]) << 12)
            ret += chr(chunk >> 16)
    elif s[-1] == "=":
            chunk = (table.index(s[-4]) << 18) | (table.index(s[-3]) << 12) | (table.index(s[-2]) << 6)
            ret += chr(chunk >> 16) + chr((chunk >> 8) & 0xff)
    else:
            chunk = (table.index(s[-4]) << 18) | (table.index(s[-3]) << 12) | (table.index(s[-2]) << 6) | table.index(s[-1])
            ret += chr(chunk >> 16) + chr((chunk >> 8) & 0xff) + chr(chunk & 0xff)

    return ret
        
#异或两个字符串
def xor_strings(string1, string2,InputType):
        '''
        takes two strings and produces the XOR sum of the bytes making them up
        args:
                string1: first string in sum
                string2: second string in sum
                InputType:first two args are encoded by hex or ASCII
        returns:
                string consisting of the XOR sum of each byte in string1 and string2
        '''
        
        if InputType == "hex":
                return ''.join([str(hex(int(x,16)^int(y,16)).replace('0x','')) for (x,y) in zip(string1,string2)])
        elif InputType == "ASCII":
                return ''.join([chr(ord(x) ^ ord(y))for (x,y) in zip(string1,string2)])
        else:
                print "third arg errors!"
                raise ValueError

def FindSingleCharXOR(SpaceNum,ciphertext):
    for char in xrange(10,127):
        result = ''.join([chr(char^ord(byte)) for byte in ciphertext])
        SpaceCount=0
        for each in result:
            if each == ' ':
                SpaceCount+=1
        if SpaceCount>=SpaceNum:
            print "char =",chr(char)
            print "The message is :",result

def pkcs7_padding(string,blocksize):
    #for a single block whose length <=blocksize
    assert (len(string) <= blocksize)
    padlen = blocksize - len(string)
    return string + chr(padlen)*padlen

def padding_plaintext(string,blocksize):
    #for entire message block to padding
    position =len(string)-len(string)%blocksize
    return string[:position] + pkcs7_padding(string[position:], blocksize)

def randbytes(n):
    return ''.join([chr(random.randint(0,255)) for _ in xrange(n)])

def aes_encrypt_block(plaintext,key):
    '''
        encrypts a 16 byte plaintext with a 16 byte key using AES-128 ECB

        args:
                pt:     plaintext to encrypt
                key:    key to encrypt with
        returns:
                ciphertext resulting from encrypting pt with the specified key
        '''
    ciphertext = AES.new(key, AES.MODE_ECB).encrypt(plaintext)
    return ciphertext

def aes_decrypt_block(ciphertext, key):
        '''
        decrypts a 16 byte ciphertext with a 16 byte key using AES-128 ECB

        args:
                ct:     ciphertext to decrypt
                key:    key to decrypt with
        returns:
                plaintext resulting from decrypting ct with the specified key
        '''

        plaintext = AES.new(key, AES.MODE_ECB).decrypt(ciphertext)
        return plaintext

def aes_ecb_encrypt(plaintext, key):
        ''' 
        encrypts an arbitrary length plaintext with a 16 byte key using AES-128 ECB

        args:
                pt:     plaintext to encrypt
                key:    key to encrypt with
        returns:
                ciphertext resulting from encrypting pt with the specified key
        '''

        AfterPading_plaintext = padding_plaintext(plaintext, 16)
        ciphertext = ""
        for i in range(0, len(AfterPading_plaintext), 16):
            ciphertext += aes_encrypt_block(AfterPading_plaintext[i:i+16], key)

        return ciphertext

def aes_ecb_decrypt(ciphertext, key):
        ''' 
        decrypts an arbitrary length ciphertext with a 16 byte key using AES-128 ECB

        args:
                ct:     ciphertext to encrypt
                key:    key to decrypt with
        returns:
                plaintext resulting from decrypting ct with the specified key
        '''

        assert(len(ciphertext) % 16 == 0)

        plaintext = ""
        for i in range(0, len(ciphertext), 16):
            plaintext += aes_decrypt_block(ciphertext[i:i+16], key)
        
        #有填充时去尾，但若加密的内容刚好够分组长度，则会引起bug
        #return plaintext[:-ord(plaintext[-1])]
        
        return plaintext

def aes_cbc_encrypt(plaintext, key, IV=randbytes(16)):
        '''
        encrypts a ciphertext with a 16 byte KEY using AES-128 CBC

        args:
                pt:     plaintext to encrypt
                key:    key to encrypt with
                IV:     initialization vector
        returns:
                ciphertext resulting from encrypting pt with specified key and IV
        '''

        assert(len(IV) == 16)
        AfterPading_plaintext = padding_plaintext(plaintext, 16)
        
        prev_ct = IV
        ciphertext = ""
        for i in range(0, len(AfterPading_plaintext), 16):
                current_ct_block = aes_encrypt_block(xor_strings(AfterPading_plaintext[i:i+16], prev_ct,"ASCII"), key)                
                ciphertext += current_ct_block
                prev_ct = current_ct_block

        return ciphertext

def aes_cbc_decrypt(ciphertext, key, IV):
        '''
        decrypts a ciphertext with a 16 byte KEY using AES-128 CBC

        args:
                ct:     ciphertext to decrypt
                key:    key to decrypt with
                IV:     initialization vector
        returns:
                plaintext resulting from decrypting ct with specified key and IV
        '''

        assert(len(IV) == 16)
        assert(len(ciphertext) % 16 == 0)        
        plaintext = ""

        prev_block = aes_decrypt_block(ciphertext[-16:], key)
        for i in range(len(ciphertext) - 16, 0, -16):
                current_ct_block = ciphertext[i-16:i]
                plaintext = xor_strings(prev_block, current_ct_block,"ASCII") + plaintext
                prev_block = aes_decrypt_block(current_ct_block, key)
        plaintext = xor_strings(prev_block, IV,"ASCII") + plaintext
        
        #有填充时去尾，但若加密的内容刚好够分组长度，则会引起bug
        #return plaintext[:-ord(plaintext[-1])]

        return plaintext


class InvalidPaddingError(RuntimeError):
   def __init__(self, arg):
      self.msg = arg


def unpad(padpt, blocksize):
        '''
        depads a plaintext padded with PKCS #7 padding scheme
        raises exception on incorrect padding 

        args:
                padpt:          padded plaintext
                blocksize:      blocksize of cipher used
        returns:
                unpadded version of padded plaintext
        exceptions:
                InvalidPaddingError on incorrect padding
        '''

        pad = padpt[-1]
        if ord(pad) > blocksize or ord(pad) == 0:
                raise InvalidPaddingError("padding character too large")

        for i in range(0, ord(pad)):
                if padpt[-i-1] != pad:
                        raise InvalidPaddingError("padding character mismatch")

        return padpt[:-ord(pad)]


def get64bits_nonce(nonce):

    '''
        args:
            nonce:  input a number 10 decimalism nonce or counter

        returns:    64 bit little endian block nonce or counter
    '''

    '''
    import struct
    struct.pack("<QQ",nonce,counter)
    '''   
    temp = hex(nonce).lstrip("0x")
    if len(temp)%2 != 0:
        temp = "0" + temp
    nonce=''
    for i in range(0,len(temp),2):
        nonce += temp[i:i+2].decode('hex')
    if len(nonce)<8:
        nonce+='\x00'*(8-len(nonce))
    return nonce


def aes_ctr_encrypt(plaintext, key, nonce):

    '''
        encrypts a plaintext using AES CTR mode

        args:
                pt:     plaintext
                key:    key to encrypt pt under
                nonce:  input a number 10 decimalism noce
                        get 64 bit little endian block nonce (byte count / 16)
        returns:
                ciphertext resulting from encrypting plaintext
    '''
    counter=0
    nonce = get64bits_nonce(nonce)
      
    ciphertext=''
    if len(plaintext)>16:
        for block_num in xrange(len(plaintext)/16):
            
            #IV = struct.pack("<QQ", nonce, counter)
            IV = nonce + get64bits_nonce(counter)
            keystream = aes_encrypt_block(IV, key)
            
            ciphertext += xor_strings(plaintext[16*block_num:16*(block_num+1)],keystream,'ASCII')
            counter+=1
            
        #handle last block
        if len(ciphertext)==16*(block_num+1):
            IV = nonce + get64bits_nonce(counter)
            keystream = aes_encrypt_block(IV, key)
           
            ciphertext+=xor_strings(plaintext[len(ciphertext):], keystream[:len(plaintext)%16], 'ASCII')

        return ciphertext
        
    else:
        #handle length<16 block
        IV = nonce + get64bits_nonce(counter)
        keystream = aes_encrypt_block(IV, key)

        ciphertext+=xor_strings(plaintext, keystream, 'ASCII')
        return ciphertext

def aes_ctr_decrypt(ciphertext, key, nonce):
    return aes_ctr_encrypt(ciphertext, key, nonce)


'--------------------------------------------------------------------------'