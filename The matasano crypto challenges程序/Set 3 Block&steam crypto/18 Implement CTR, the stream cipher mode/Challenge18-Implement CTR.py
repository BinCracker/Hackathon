#coding:utf-8
from code import *

target = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="

def check():
    test = aes_ctr_encrypt("hello", 'x'*16, 0)
    iv = Counter.new(64,prefix='\x00'*8,initial_value=0,little_endian=True)
    target = AES.new('x'*16, AES.MODE_CTR,counter=iv).encrypt("hello")

    if test == target:
        return True
    else:
        return False

def main():
    try:
        assert(check())
    except:
        print "function implement error!"

    print aes_ctr_decrypt(b64decode(target),"YELLOW SUBMARINE", 0)

if __name__ == '__main__':
    main()

    
