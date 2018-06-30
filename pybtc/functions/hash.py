import hashlib
import hmac


def sha256(h, hex=False):
    if type(h) == str:
        h = bytes.fromhex(h)
    if hex:
        return hashlib.sha256(h).hexdigest()
    return hashlib.sha256(h).digest()


def double_sha256(h, hex=False):
    if type(h) == str:
        h = bytes.fromhex(h)
    if hex:
        return sha256(sha256(h), 1)
    return sha256(sha256(h))


def hmac_sha512(key, data, hex=False):
    if hex:
        return hmac.new(key, data, hashlib.sha512).hexdigest()
    return hmac.new(key, data, hashlib.sha512).digest()


def ripemd160(h, hex=False):
    if type(h) == str:
        h = bytes.fromhex(h)
    a = hashlib.new('ripemd160')
    a.update(h)
    if hex:
        return a.hexdigest()
    return a.digest()


def hash160(h, hex=False):
    if type(h) == str:
        bytes.fromhex(h)
    if hex:
        return ripemd160(sha256(h), 1)
    return ripemd160(sha256(h))

