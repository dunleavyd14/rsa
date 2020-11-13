import hashlib
import random
import math
from itertools import count
from typing import Tuple


def sha256(msg : str) -> str:
	return hashlib.sha256(msg.encode()).hexdigest()


def gcd(a : int, b : int) -> int:
	
	r = a % b
	if r == 0:
		return b
	else:
		a, b = b, r
		return gcd(a, b)

def lcm(a : int, b : int) -> int:
	return a*b//gcd(a, b)



def miller_rabin(n : int, k : int) -> bool:
	if n % 2 == 0:
		return False

	d = n - 1
	while not d % 2:
		d //= 2
	
	def test(d, n):
		a = random.randint(2, n - 2)
		r = pow(a, d, n)

		if r == 1 or r == n - 1:
			return True

		while d != n - 1:
			r = r**2 % n
			d *= 2

			if r == 1:
				return False
			
			if r == n-1:
				return True
		return False
	
	
	
	return all([test(d, n) for _ in range(k)])


def get_prime(limit : int) -> int:
	#allegedly openSSL uses this method, so it must be decent
	p = random.randint(5, limit)
	if p % 2 == 0:
		p += 1
	
	while not miller_rabin(p, 100):
		if p > limit:
			#force overflow b/c python ints are unbounded
			p = random.randint(5, limit)
		p += 2
	
	return p



def rsa_keygen() -> Tuple[int, int, int]:
	p = get_prime(2**256)
	q = get_prime(2**256)
	n = p*q

	lmbda = lcm(p - 1, q - 1)
	e = 2**16 + 1

	d = pow(e, -1, lmbda)

	return n, e, d



def test(n : int, e : int, d : int):
	message = 100

	encrypted = pow(message, e, n)
	decrypted = pow(encrypted, d, n)

	print(message, encrypted, decrypted)


test(*rsa_keygen())












