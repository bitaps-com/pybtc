from hashlib import new as hashlib_new
from hashlib import sha512 as hashlib_sha512
from pybtc.crypto import __double_sha256__
from pybtc.crypto import __sha256__
from pybtc.crypto import __siphash__
from pybtc.crypto import __murmurhash3__
from pybtc.crypto import __sha3_256__
from pybtc.functions.tools import get_bytes
import hmac

bytes_from_hex = bytes.fromhex


def siphash(h, v_0=0, v_1=0, encoding = None):
    """
    Calculate siphash from byte string

    :param h: byte string or HEX encoded string
    :param v_0: randomization  vector 0  64 bit integer
    :param v_1:  randomization  vector 1  64 bit integer
    :return: hash as 64 bit integer
    """
    h = get_bytes(h, encoding=encoding)
    return __siphash__(v_0, v_1, h)


def murmurhash3(seed, h, encoding = None):
    """
    Calculate murmurhash3 from byte string

    :param h: byte string or HEX encoded string
    :param seed: seed randomization vector integer
    :return: hash as integer
    """

    h = get_bytes(h, encoding=encoding)
    return __murmurhash3__(seed, h)



def sha256(h, hex=False, encoding=None):
    h = get_bytes(h, encoding=encoding)
    return __sha256__(h).hex() if hex else __sha256__(h)


def sha3_256(h, hex=False, encoding=None):
    h = get_bytes(h, encoding=encoding)
    return __sha3_256__(h).hex() if hex else __sha3_256__(h)


def double_sha256(h, hex=False, encoding=None):
    h = get_bytes(h, encoding=encoding)
    return __double_sha256__(h).hex() if hex else __double_sha256__(h)


def hmac_sha512(key, data, hex=False, encoding=None):
    key = get_bytes(key, encoding=encoding)
    data = get_bytes(data, encoding=encoding)
    if hex:
        return hmac.new(key, data, hashlib_sha512).hexdigest()
    return hmac.new(key, data, hashlib_sha512).digest()


def ripemd160(h, hex=False, encoding=None):
    h = get_bytes(h, encoding=encoding)
    a = hashlib_new('ripemd160')
    a.update(h)
    return a.hexdigest() if hex else a.digest()


def hash160(h, hex=False, encoding=None):
    h = get_bytes(h, encoding=encoding)
    return ripemd160(sha256(h), True) if hex else ripemd160(sha256(h))


