
y = 0x2d026f4bf30195ede3a088da85e398ef869611d0f68f0713d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b85519b1c23cc3ecdc6062650462e3063bd179c2a6581519f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d32971c3de5084cce04a2e147821
q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b

s1 = 1267396447369736888040262262183731677867615804316
r1 = 1105520928110492191417703162650245113664610474875
m1 = 0xa4db3de27e2db3e5ef085ced2bced91b82e0df19

s2 = 559339368782867010304266546527989050544914568162
r2 = 826843595826780327326695197394862356805575316699
m2 = 0x88b9e184393408b133efef59fcef85576d69e249

def egcd(a, b):
    if b == 0:
        return (1, 0)
    else:
        q = a // b
        r = a % b
        (s, t) = egcd(b, r)
        return (t, s - q * t)

# Returns a^-1 mod N
def invmod(a, N):
    
    (x, y) = egcd(a, N)
    return x % N

def recover_dsa_k(hash1, hash2, r1, s1, r2, s2, q=q):
	'''
	       (m1 - m2)
	   k = --------- mod q
	       (s1 - s2)
	'''

	top = (hash1 - hash2) % q
	k = top * invmod((s1 - s2)%q, q)
	return k

def get_dsa_key_from_known_k(r, s, k, msg_hash, q=q):
	'''
	x is private key
	      (s * k) - H(msg)
	  x = ----------------  mod q
	              r
	'''

	top = ((s*k) - msg_hash) % q
	x = top * invmod(r, q)
	return x

if __name__ == "__main__":
    k = recover_dsa_k(m1, m2, r1, s1, r2, s2)
    x1 = get_dsa_key_from_known_k(r1, s1, k, m1)
    x2 = get_dsa_key_from_known_k(r1, s1, k, m1)
    assert(x1 == x2)
    print("x = ", x1)
    print("problem 44 success")