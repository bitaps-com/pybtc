from .hash import double_sha256

b58_digits = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
base32charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
base32charset_upcase = "QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L"

int_base32_map = dict()
base32_int_map = dict()

for n, i in enumerate(base32charset):
    int_base32_map[i] = n
    base32_int_map[n] = ord(i)
for n, i in enumerate(base32charset_upcase):
    int_base32_map[i] = n


def rebasebits(data, frombits, tobits, pad=True):
    """General power-of-2 base conversion."""
    acc = 0
    bits = 0
    ret = bytearray()
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            raise ValueError("invalid bytes")
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        raise ValueError("invalid padding")
    return ret


def rebase_5_to_8(data, pad = True):
    return rebasebits(data, 5, 8, pad)


def rebase_8_to_5(data, pad = True):
    return rebasebits(data, 8, 5, pad)


def rebase_32_to_5(data):
    if type(data) == bytes:
        data = data.decode()
    b = bytearray()
    try:
        for i in data:
            b.append(int_base32_map[i])
    except:
        raise Exception("Non base32 characters")
    return b


def rebase_5_to_32(data, bytes = True):
    r = bytearray()
    for i in data:
        r.append(base32_int_map[i])
    return r.decode() if not bytes else r


def bech32_polymod(values):
    """Internal function that computes the Bech32 checksum."""
    generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk ^ 1


def encode_base58(b):
    """Encode bytes to a base58-encoded string"""
    # Convert big-endian bytes to integer

    n= int('0x0' + b.hex(), 16)

    # Divide that integer into bas58
    res = []
    while n > 0:
        n, r = divmod(n, 58)
        res.append(b58_digits[r])
    res = ''.join(res[::-1])
    # Encode leading zeros as base58 zeros
    czero = 0
    pad = 0
    for c in b:
        if c == czero:
            pad += 1
        else:
            break
    return b58_digits[0] * pad + res


def decode_base58(s):
    """Decode a base58-encoding string, returning bytes"""
    if not s:
        return b''
    # Convert the string to an integer
    n = 0
    for c in s:
        n *= 58
        if c not in b58_digits:
            raise Exception('Character %r is not a valid base58 character' % c)
        digit = b58_digits.index(c)
        n += digit
    # Convert the integer to bytes
    h = '%x' % n
    if len(h) % 2:
        h = '0' + h
    res = bytes.fromhex(h)
    # Add padding back.
    pad = 0
    for c in s[:-1]:
        if c == b58_digits[0]:
            pad += 1
        else:
            break
    return b'\x00' * pad + res


def encode_base58_with_checksum(b):
    return encode_base58(b"%s%s" % (b, double_sha256(b)[:4]))


def decode_base58_with_checksum(s):
    b = decode_base58(s)
    assert double_sha256(b[:-4])[:4] == b[-4:]
    return b[:-4]
