from math import ceil, floor
from io import BytesIO
from struct import pack, unpack
from pybtc.crypto import __map_into_range__


bytes_from_hex = bytes.fromhex
int_from_bytes = int.from_bytes


def get_bytes(s, encoding = None):
    if isinstance(s, list):
        try:
            s = b"".join(s)
        except:
            try:
                s = "".join(s)
            except:
                try:
                    s = [n if isinstance(n,bytes) else bytes_from_hex(n) for n in s]
                    s = b"".join(s)
                except: # pragma: no cover
                    raise ValueError("invalid list")
    if isinstance(s, bytes) or isinstance(s, bytearray):
        return s
    if isinstance(s, str):
        if encoding == 'utf8':
            return s.encode()
        elif encoding == 'hex':
            return bytes_from_hex(s)
        try:
            return bytes_from_hex(s)
        except:
            return s.encode()

    raise ValueError("utf8 string/hex string/byte string required")


def rh2s(raw_hash):
    """
    Encode raw transaction hash to HEX string with bytes order change

    :param raw_hash: transaction hash in bytes string.
    :return:  HEX encoded string.
    """
    return raw_hash[::-1].hex()


def s2rh(hash_string):
    """
    Decode HEX  transaction hash to bytes with byte order change

    :param raw_hash: transaction hash in bytes string.
    :return:  bytes string.
    """
    return bytes_from_hex(hash_string)[::-1]


def s2rh_step4(hash_string):
    h = bytes_from_hex(hash_string)
    return reverse_hash(h)


def reverse_hash(raw_hash):
    """
    Reverse hash order

    :param raw_hash: bytes string.
    :return:  bytes string.
    """
    return pack('>IIIIIIII', * unpack('>IIIIIIII', raw_hash)[::-1])[::-1]


def bytes_needed(n):
    """
    Calculate bytes needed to convert integer to bytes.

    :param n: integer.
    :return: integer.
    """
    return ceil(n.bit_length()/8) if n != 0 else 1


def int_to_bytes(i, byteorder='big'):
    """
    Convert integer to bytes.

    :param n: integer.
    :param byteorder: (optional) byte order 'big' or 'little', by default 'big'.
    :return: bytes.
    """
    return i.to_bytes(bytes_needed(i), byteorder=byteorder, signed=False)


def bytes_to_int(i, byteorder='big'):
    """
    Convert bytes to integer.

    :param i: bytes.
    :param byteorder: (optional) byte order 'big' or 'little', by default 'big'.
    :return: integer.
    """
    return int_from_bytes(i, byteorder=byteorder, signed=False)


# variable integer

def int_to_var_int(i):
    """
    Convert integer to variable integer

    :param i: integer.
    :return: bytes.
    """
    if i < 0xfd:
        return pack('<B', i)
    if i <= 0xffff:
        return b'\xfd%s' % pack('<H', i)
    if i <= 0xffffffff:
        return b'\xfe%s' % pack('<L', i)
    return b'\xff%s' % pack('<Q', i)


def var_int_to_int(data):
    """
    Convert variable integer to integer

    :param data: bytes variable integer.
    :return: integer.
    """
    if data[0] == 0xfd:
        return unpack('<H', data[1:3])[0]
    elif data[0] == 0xfe:
        return unpack('<L', data[1:5])[0]
    elif data[0] == 0xff:
        return unpack('<Q', data[1:9])[0]
    return data[0]


def var_int_len(n):
    """
    Get variable integer length in bytes from integer value

    :param n: integer.
    :return: integer.
    """
    if n <= 0xfc:
        return 1
    if n <= 0xffff:
        return 3
    elif n <= 0xffffffff:
        return 5
    return 9


def get_var_int_len(bytes):
    """
    Get variable integer length in bytes from bytes

    :param bytes: bytes.
    :return: integer.
    """
    if bytes[0] == 253:
        return 3
    elif bytes[0] == 254:
        return 5
    elif bytes[0] == 255:
        return 9
    return 1


def read_var_int(stream):
    """
    Read variable integer from io.BytesIO stream to bytes

    :param stream: io.BytesIO stream.
    :return: bytes.
    """
    l = stream.read(1)
    if l[0] == 253:
        s = 3
    elif l[0] == 254:
        s = 5
    elif l[0] == 255:
        s = 9
    else:
        return l
    return b"".join((l, stream.read(s - 1)))


def read_var_list(stream, data_type): # pragma: no cover
    """
    Read variable integer list from io.BytesIO stream to bytes

    :param stream: io.BytesIO stream.
    :param data_type: list data type.
    :return: list of data_type.
    """
    deserialize = data_type.deserialize
    count = var_int_to_int(read_var_int(stream))
    return [deserialize(stream) for i in range(count)]

# compressed integer

def int_to_c_int(n, base_bytes=1):
    """
    Convert integer to compressed integer
    :param n: integer.
    :param base_bytes: len of bytes base from which start compression.
    :return: bytes.
    """
    if n == 0:
        return b'\x00' * base_bytes
    else:
        l = n.bit_length() + 1
    if l <= base_bytes * 8:
        return n.to_bytes(base_bytes, byteorder="big")
    prefix = 0
    payload_bytes = ceil((l)/8) - base_bytes
    a=payload_bytes
    while True:
        add_bytes = floor((a) / 8)
        a = add_bytes
        if add_bytes>=1:
            add_bytes+=floor((payload_bytes+add_bytes) / 8) - floor((payload_bytes) / 8)
            payload_bytes+=add_bytes
        if a==0: break
    extra_bytes = int(ceil((l+payload_bytes)/8) - base_bytes)
    for i in range(extra_bytes):
        prefix += 2 ** i
    if l < base_bytes * 8: # pragma: no cover
        l = base_bytes * 8
    prefix = prefix << l
    if prefix.bit_length() % 8:
        prefix = prefix << 8 - prefix.bit_length() % 8
    n ^= prefix
    return n.to_bytes(ceil(n.bit_length() / 8), byteorder="big")


def c_int_len(n, base_bytes=1):
    """
    Get length of compressed integer from integer value
    :param n: bytes.
    :param base_bytes: len of bytes base from which start compression.
    :return: integer.
    """
    if n == 0:
        return base_bytes
    l = n.bit_length() + 1
    if l <= base_bytes * 8:
        return base_bytes
    payload_bytes = ceil((l) / 8) - base_bytes
    a = payload_bytes
    while True:
        add_bytes = floor((a) / 8)
        a = add_bytes
        if add_bytes >= 1:
            add_bytes += floor((payload_bytes + add_bytes) / 8) - floor((payload_bytes) / 8)
            payload_bytes += add_bytes
        if a == 0: break
    return int(ceil((l+payload_bytes)/8))


def c_int_to_int(b, base_bytes=1):
    """
    Convert compressed integer bytes to integer

    :param b: compressed integer bytes.
    :param base_bytes: len of bytes base from which start compression.
    :return: integer.
    """
    byte_length = 0
    f = 0
    while True:
        v = b[f]
        if v == 0xff:
            byte_length += 8
            f += 1
            continue
        while v & 0b10000000:
            byte_length += 1
            v = v << 1
        break
    n = int_from_bytes(b[:byte_length+base_bytes], byteorder="big")
    if byte_length:
        return n & ((1 << (byte_length+base_bytes) * 8 - byte_length) - 1)
    return n


def read_c_int(stream, base_bytes=1):
    """
    Read compressed integer from io.BytesIO stream to bytes

    :param stream: io.BytesIO stream.
    :return: bytes.
    """
    b = bytearray(stream.read(1))
    byte_length = f = 0
    while True:
        v = b[f]
        if v == 0xff:
            byte_length += 8
            f += 1
            b += stream.read(1)
            continue
        while v & 0b10000000:
            byte_length += 1
            v = v << 1
        break
    b += stream.read(byte_length+base_bytes - f - 1)
    return b


# generic big endian MPI format
def bn_bytes(v, have_ext=False):
    ext = 0
    if have_ext:
        ext = 1
    return ((v.bit_length() + 7) // 8) + ext


def bn2bin(v):
    s = bytearray()
    i = bn_bytes(v)
    while i > 0:
        s.append((v >> ((i - 1) * 8)) & 0xff)
        i -= 1
    return s


def bin2bn(s):
    l = 0
    for ch in s:
        l = (l << 8) | ch
    return l


def bn2mpi(v):
    have_ext = False
    if v.bit_length() > 0:
        have_ext = (v.bit_length() & 0x07) == 0
    neg = False
    if v < 0:
        neg = True
        v = -v
    s = pack(b">I", bn_bytes(v, have_ext))
    ext = bytearray()
    if have_ext:
        ext.append(0)
    v_bin = bn2bin(v)
    if neg:
        if have_ext:
            ext[0] |= 0x80
        else:
            v_bin[0] |= 0x80
    return s + ext + v_bin


def mpi2bn(s):
    if len(s) < 4:
        return None
    s_size = bytes(s[:4])
    v_len = unpack(b">I", s_size)[0]
    if len(s) != (v_len + 4):
        return None
    if v_len == 0:
        return 0
    v_str = bytearray(s[4:])
    neg = False
    i = v_str[0]
    if i & 0x80:
        neg = True
        i &= ~0x80
        v_str[0] = i
    v = bin2bn(v_str)

    if neg:
        return -v
    return v

# bitcoin-specific little endian format, with implicit size


def mpi2vch(s):
    r = s[4:]           # strip size
    r = r[::-1]         # reverse string, converting BE->LE
    return r


def bn2vch(v):
    return bytes(mpi2vch(bn2mpi(v)))


def vch2mpi(s):
    r = pack(b">I", len(s))   # size
    r += s[::-1]            # reverse string, converting LE->BE
    return r


def vch2bn(s):
    return mpi2bn(vch2mpi(s))


def i2b(i): return bn2vch(i)


def b2i(b): return vch2bn(b)


def get_stream(stream):
    if not isinstance(stream, BytesIO):
        if isinstance(stream, str):
            stream = bytes_from_hex(stream)
        if isinstance(stream, bytes):
            stream = BytesIO(stream)
        else:
            raise TypeError
    return stream

def map_into_range(element, m_f):
    return __map_into_range__(element, m_f)


def hash_to_random_vectors(h):
    if isinstance(h, str):
        h = s2rh(h)
    return bytes_to_int(h[:8], byteorder="little"),\
           bytes_to_int(h[8:16],  byteorder="little")
