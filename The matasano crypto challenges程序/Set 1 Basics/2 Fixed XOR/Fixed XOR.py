#!/usr/bin/python2
from code import *

string = '1c0111001f010100061a024b53535009181c'
target = '746865206b696420646f6e277420706c6179'
xor = '686974207468652062756c6c277320657965'


if __name__ == '__main__':
        if xor_strings(string,xor,"hex")==target:
                print "Succeed!"
                print target

