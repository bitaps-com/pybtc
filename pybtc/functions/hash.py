from hashlib import new as hashlib_new
from hashlib import sha256 as hashlib_sha256
from hashlib import sha512 as hashlib_sha512
from pybtc.crypto import __double_sha256__
from pybtc.crypto import __sha256__
import hmac

bytes_from_hex = bytes.fromhex

def sha256(h, hex=False):
    if isinstance(h, str):
        h = bytes_from_hex(h)
    # return hashlib_sha256(h).hexdigest() if hex else hashlib_sha256(h).digest()
    return __sha256__(h).hex() if hex else __sha256__(h)


def double_sha256(h, hex=False):
    if not isinstance(h, bytes):
        if isinstance(h,str):
            h = bytes_from_hex(h)
        # if isinstance(h, bytearray):
        #     h = bytes(h)
    # return hashlib_sha256(hashlib_sha256(h).digest()).digest()
    return __double_sha256__(h).hex() if hex else __double_sha256__(h)


def hmac_sha512(key, data, hex=False):
    if hex:
        return hmac.new(key, data, hashlib_sha512).hexdigest()
    return hmac.new(key, data, hashlib_sha512).digest()


def ripemd160(h, hex=False):
    if isinstance(h, str):
        h = bytes_from_hex(h)
    a = hashlib_new('ripemd160')
    a.update(h)
    return a.hexdigest() if hex else a.digest()


def hash160(h, hex=False):
    if isinstance(h, str):
        bytes_from_hex(h)
    return ripemd160(sha256(h), True) if hex else ripemd160(sha256(h))


