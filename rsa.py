import hashlib
import random
import math
from itertools import count
from typing import Tuple
import os
import secrets


E = 2**16 + 1

def sha256(msg : bytes) -> str:
	return hashlib.sha256(msg).digest()


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




def rsa_keygen() -> Tuple[int, int]:
	p = get_prime(2**512)
	q = get_prime(2**512)
	n = p*q


	lmbda = lcm(p - 1, q - 1)
	e = 2**16 + 1

	d = pow(E, -1, lmbda)

	return n, d

def record_keys(pub : int, priv : int, fname : str):
	with open(fname + "_pub", "w") as f:
		f.write(str(pub))

	with open(fname + "_pri", "w") as f:
		f.write(str(priv))
	
	print("Public key:", pub)
	print("Private key:", priv)

def OAEP(msg : bytes) -> int:
	while len(msg)*8 < 256:
		msg += b"\x00"
	rand_bytes = os.urandom(256//8)

	first = bytewise_xor(msg, sha256(rand_bytes))
	second = bytewise_xor(sha256(first), rand_bytes)

	return int.from_bytes(first + second, "big")

def remove_OAEP(msg : int) -> bytes:
	dec = msg.to_bytes(512//8, "big")
	
	first = dec[:256//8]
	second = dec[256//8:]

	rand = bytewise_xor(second, sha256(first))

	return bytewise_xor(first, sha256(rand))
	
def bytewise_xor(x : bytes, y : bytes) -> bytes:
	return bytes([i ^ j for i, j in zip(x, y)])


def encrypt(msg : bytes, fname : str, out_fname : str):
	with open(fname + "_pub", "r") as f:
		pub_key = int(f.read())
	
	encrypted = pow(OAEP(msg), E, pub_key)

	with open(out_fname, "wb") as f:
		final = encrypted.to_bytes(1024//8, "big")
		f.write(final)
	
	print("Encrypted message:", final)

def decrypt(msg_fname: str, fname : str):
	with open(msg_fname, "rb") as f:
		enc = int.from_bytes(f.read(), "big")
	
	with open(fname + "_pri", "r") as f:
		pri_key = int(f.read())
	
	with open(fname + "_pub", "r") as f:
		pub_key = int(f.read())

	
	dec = pow(enc, pri_key, pub_key)

	msg = remove_OAEP(dec)
	print("Message:", msg)

def test(n : int, d : int, message : bytes):
	m = OAEP(b"hello")
	encrypted = pow(m, E, n)
	decrypted = pow(encrypted, d, n)

	final = remove_OAEP(decrypted)

	print(final)

if __name__ == "__main__":
	import sys

	if len(sys.argv) == 1:
		print(
				"Usage:	keygen key_name"
				"		encrypt message key_name output_filename"
				"		decrypt msg_filename key_name"
			)
	
	command = sys.argv[1]
	if command == "test":
		pub, priv = rsa_keygen()
		record_keys(pub, priv, "test")
		encrypt("hello".encode(), "test", "test_enc")
		decrypt("test_enc", "test")

	elif command == "keygen":
		fname = sys.argv[2]
		pub, priv = rsa_keygen()
		record_keys(pub, priv, fname)
	
	elif command == "encrypt":
		msg, key, output_fname = sys.argv[2].encode(), sys.argv[3], sys.argv[4]
		encrypt(msg, key, output_fname)
	
	elif command == "decrypt":
		msg_fname, key = sys.argv[2], sys.argv[3]
		decrypt(msg_fname, key)

















