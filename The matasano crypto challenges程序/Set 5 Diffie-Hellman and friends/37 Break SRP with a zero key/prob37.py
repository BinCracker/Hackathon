#coding: UTF-8
from prob36 import _p,_g,_k,I,P,step1,step2,step3,step4,step5,step6,step7,srp_success,intToBytes
from hashlib import sha256
from random import randrange

def srp():
    state = {"p" : _p,
             "g" : _g,
             "k" : _k,
             "I": I,
             "P": P        
        }
    state = step1(state);
    state = step2(state);
    state = step3(state);
    state = step4(state);
    state = step5(state);
    state = step6(state);
    state = step7(state);
    if(srp_success(state)==False):
        print("failed");
    print("srp succ");

#让客户端发送 0 作为 "A" 的值
''' A = 0 -> S = (A * v**u) ** b % N = 0
   S = 0 
'''
def client0():
    state = {"p" : _p,
             "g" : _g,
             "k" : _k,
             "I": I,
             "P": P        
        }
    state = step1(state);
    state = step2(state);
    state["A"] = 0;
    state = step3(state);
    state = step4(state);
# 客户端没有密钥
    state["C_K"] = sha256(intToBytes(0)).digest();
    state = step6(state);
    state = step7(state);
    if (srp_success(state)==False):
        print("failed");
    print("client0 succ");
#让客户端发送 N, N*2, &c，不通过密钥登录
'''
if A = k * N  ->  S = (A * v**u) **b % N == 0 mod N == 0
'''
def clientx():
    state = {"p" : _p,
             "g" : _g,
             "k" : _k,
             "I": I,
             "P": P        
        }
    state = step1(state);
    state = step2(state);
    k = randrange(1, 30)
    state["A"] = k*_p;
    state = step3(state);
    state = step4(state);
    #客户端没有密钥
    state["C_K"] = sha256(intToBytes(0)).digest();
    state = step6(state);
    state = step7(state);
    if (srp_success(state)==False):
        print("failed");
    print("clientx succ");
if __name__ == "__main__":
     print("start");
     srp();
     client0();
     clientx();
