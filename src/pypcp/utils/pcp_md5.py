import hashlib

MD5_PASSWD_LEN=32

WD_AUTH_HASH_LEN=64

def pool_md5_hash(buff):
	result = hashlib.md5(buff)
	return result.hexdigest()

def pool_md5_encrypt(passwd, salt):
	"""
	Place salt at the end because it may be known by users trying to crack
	the MD5 output.
	"""
	crypt_buf = passwd + salt
	result = pool_md5_hash(crypt_buf)
	return result
