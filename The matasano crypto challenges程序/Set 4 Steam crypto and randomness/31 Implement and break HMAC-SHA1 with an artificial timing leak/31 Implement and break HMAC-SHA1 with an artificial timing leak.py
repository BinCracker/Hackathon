#!/usr/bin/python2
#!Encoding=utf-8
import hashlib
import time
import datetime

def hmac(key,message):#hmac为在sha-1的基础上再次定义的包含自定义key的hash函数
	blocksize=16
	hexkey=key[:16].zfill(blocksize).encode('hex')
	enckey=str(hex(int(hexkey,16)^0x1234567890abcdef1234567890abcdef)[2:-1]).decode('hex')
	enc_message=enckey+message
	return hashlib.sha1(enc_message).hexdigest()

def check(str1,str2):#模拟服务端，方便调试
	for i,j in zip(str1,str2):
		if i != j:
			return 0
		time.sleep(0.05)#对比正确就延时50ms
	return 1

def hashfork(signature):#hash伪造
	keyspcae='0123456789abcdefghijklmnopqrstuvwxyz'
	forkkey=list('0'*32)
	#forkkey=list(signature[:1]+''.join(forkkey)[1:])
	count=1
	for i in range(len(forkkey)):
		for j in range(len(keyspcae)):
			forkkey[i]=keyspcae[j]
			starttime = datetime.datetime.now()
			if check(signature,''.join(forkkey)):
				print 'succsess!!'
			endtime = datetime.datetime.now()
			interval=(endtime - starttime).microseconds+(endtime - starttime).seconds*1000
			#print interval,''.join(forkkey),i,j
			if interval >= count*50000:
				count+=1
				break
		print interval,''.join(forkkey),i,j
		#raw_input('>')
	print forkkey#伪造成功

message='foo'
key='abcdee'
signature=hmac(key,message)
print signature#正确的hash值
hashfork(signature)#hash伪造
#验证时间过长，由前几个字符的结果可以看出代码可以成功