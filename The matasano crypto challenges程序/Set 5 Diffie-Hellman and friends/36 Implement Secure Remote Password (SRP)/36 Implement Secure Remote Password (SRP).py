#!/usr/bin/env python3.5
#https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol#Implementation_example_in_Python
from hashlib import sha256
from random import randrange
_p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
_g = 2;
_k = 3;
I = b'fpcsong@sina.com'
P = b'AzureFat'
def myhmac(hash_function, message, key):
    blocksize = hash_function().block_size;
    if (len(key) > blocksize):
        key = hash_function(key).digest()
    if (len(key) < blocksize):
        key += (b'\x00' * (blocksize - len(key)));

    opad = raw_xor(b'\x5c' * blocksize, key);
    ipad = raw_xor(b'\x36' * blocksize, key);
    
    return hash_function(opad + hash_function(ipad + message).digest()).digest();

def quickpow(a, b, c): # a^b mod c
    if (b == 0):
        return 1 
    if (b == 1):
        return (a % c)
    b_bits = bin(b)[2:] 
    res = a;
    for i in range(1, len(b_bits)):           
        res = res * res;       
        if (b_bits[i] == '1' ):
            res = res * a;       
        res = res % c;
    return res;
def intToBytes(integer):
    hex_form = hex(integer)[2:]; 
    if (len(hex_form) % 2):
        hex_form = '0' + hex_form;
    return bytearray.fromhex(hex_form)
def raw_xor(in1, in2):
    length = min(len(in1), len(in2));
    result = [(in1[i] ^ in2[i]).to_bytes(1, byteorder='big') for i in range(length)];
    return b''.join(result);
def init():
    state = {"p" : _p,
             "g" : _g,
             "k" : _k,
             "I": I,
             "P": P        
        }
    return state;
#Generate salt as random integer
#Generate string xH=SHA256(salt|password)
#Convert xH to integer x somehow (put 0x on hexdigest)
#Generate v=g**x % N
#Save everything but x, xH
def step1(state):
    salt = randrange(2, state["p"]-2);
    xH = sha256(intToBytes(salt) + state["P"]).hexdigest();
    x = int(xH, 16);
    v = quickpow(state["g"], x, state["p"]);
    state["v"] = v;
    state["salt"] = salt;
    return state;
#Send I, A=g**a % N (a la Diffie Hellman)
def step2(state):
    state["a"] = randrange(2, state["p"]-2);
    state["A"] = quickpow(state["g"], state["a"], state["p"]);
    return state;
#Send salt, B=kv + g**b % N
def step3(state):
    state["b"] = randrange(2, state["p"]-2);
    state["B"] = (state["k"] * state["v"] + quickpow(state["g"], state["b"], state["p"]));
    return state;
#Compute string uH = SHA256(A|B), u = integer of uH
def step4(state):
    uH = sha256(intToBytes(state["A"]) + intToBytes(state["B"])).hexdigest();
    state["u"] = int(uH, 16);
    return state;
#Generate string xH=SHA256(salt|password)
#Convert xH to integer x somehow (put 0x on hexdigest)
#Generate S = (B - k * g**x)**(a + u * x) % N
#Generate K = SHA256(S)
def step5(state):
    xH = sha256(intToBytes(state["salt"]) + state["P"]).hexdigest();
    x = int(xH, 16);
    S = quickpow((state["B"] - state["k"] * quickpow(state["g"], x, state["p"])), (state["a"] + state["u"] * x), state["p"]);
    state["C_K"] = sha256(intToBytes(S)).digest();
    return state;
#Generate S = (A * v**u) ** b % N
#Generate K = SHA256(S)
def step6(state):
    S = quickpow(state["A"] * quickpow(state["v"], state["u"], state["p"]), state["b"], state["p"]);
    state["S_K"] = sha256(intToBytes(S)).digest();
    return state;
#Send HMAC-SHA256(K, salt)
def step7(state):
    state["challenge"] = myhmac(sha256, state["C_K"], intToBytes(state["salt"]));
    return state;
#Send "OK" if HMAC-SHA256(K, salt) validates
def srp_success(state):
    expected = myhmac(sha256, state["S_K"], intToBytes(state["salt"]));
    return expected == state["challenge"];
def test():
    state = init();
    state = step1(state);
    state = step2(state);
    state = step3(state);
    state = step4(state);
    state = step5(state);
    state = step6(state);
    state = step7(state);
    if (srp_success(state)):
        print("Success");
    else:
        print("Not success");
if __name__ == "__main__":
    test();
