#include<bits/stdc++.h>
using namespace std;
int MT[624];
int index;
bool isInit;
void Init(int seed){
	index = 0;
	isInit = true;
	MT[0] = seed;
	for (int i = 0 ; i < 624 ; i++){
		int tmp = 1812433253 * (MT[i - 1] ^ MT[i - 1]>>30) + i;
		MT[i] = tmp & 0xffffffff;
	}
}
void gener(){
	for (int i = 0 ; i < 624; i++){
		int tmp = (MT[i] & 0x80000000) + (MT[(i + 1) % 624] & 0x7fffffff);
		MT[i] = MT[(i + 397) % 624] ^ (tmp >> 1);
		if (tmp & 1)
			MT[i] ^= 2567483615;
	}
}
int RNG(){
	if (!isInit) Init((int) time(NULL));
	if (!index) gener();
	int tmp = MT[index];
	tmp ^= (tmp >> 11);
	tmp ^= ((tmp << 7) & 2636928640);
	tmp ^= ((tmp << 15) & 4022730752);
	tmp ^= (tmp >> 18);
	index = (index + 1) % 624;
	return tmp;
}
int main(){
	for (int i = 1 ; i <= 10000; i++)
		cout<< RNG()<<' ';
	return 0;
}
