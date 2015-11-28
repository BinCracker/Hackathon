#!/usr/bin/python2
#!Encoding=utf-8
import hashlib
import time
import datetime

#do something



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
		time.sleep(0.005)#对比正确就延时50ms
	return 1

def hashfork(signature,forkkey=list('0'*40),start=0):#hash伪造
	keyspcae='0123456789abcdefghijklmnopqrstuvwxyz#'
	#forkkey=list(signature[:1]+''.join(forkkey)[1:])
	count=1+start
	for i in range(start,len(forkkey)):
		j=0
		print ''.join(forkkey)
		while j<len(keyspcae):
			forkkey[i]=keyspcae[j]
			starttime = datetime.datetime.now()
			if check(signature,''.join(forkkey)):
				print 'succsess!!the forkhash is %s'%''.join(forkkey)
			endtime = datetime.datetime.now()
			interval=(endtime - starttime).microseconds+(endtime - starttime).seconds*1000
			#print interval,''.join(forkkey),i,j
			if interval >= count*5000:
				count +=1
				break
			j+=1
			if keyspcae[j]=='#':#由于时间过短，网络延迟导致执行时间过长
				print 'error',count-2
				return 0
		#raw_input('>')

message='foo'
key='abcdee'
#e12fbddce27540bf08682608dd1b5fe9f04ee3f1
signature=hmac(key,message)
#hashfork(signature)
#下面是出错的时候手工构造的举例
#假设在e12fbddce27540bf086820000000000000000000时出错，定位位置
hashfork(signature,forkkey=list('e12fbddce27540bf086820000000000000000000'),start=21)#hash伪造
#此处的forkkey允许初始化，方便因为延迟导致字符被放行的时候，能够实现从出错的地方继续构造
#error标示的是出错的位置，起始值为error的值