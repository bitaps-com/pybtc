import math
import io
import struct


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
    return bytes.fromhex(hash_string)[::-1]


def s2rh_step4(hash_string):
    h = bytes.fromhex(hash_string)
    return reverse_hash(h)


def reverse_hash(raw_hash):
    """
    Reverse hash order

    :param raw_hash: bytes string.
    :return:  bytes string.
    """
    return struct.pack('>IIIIIIII', *struct.unpack('>IIIIIIII', raw_hash)[::-1])[::-1]


def bytes_needed(n):
    """
    Calculate bytes needed to convert integer to bytes.

    :param n: integer.
    :return: integer.
    """
    if n == 0:
        return 1
    return math.ceil(n.bit_length()/8)


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
    return int.from_bytes(i, byteorder=byteorder, signed=False)


# variable integer

def int_to_var_int(i):
    """
    Convert integer to variable integer

    :param i: integer.
    :return: bytes.
    """
    if i < 0xfd:
        return struct.pack('<B', i)
    if i <= 0xffff:
        return b'\xfd%s' % struct.pack('<H', i)
    if i <= 0xffffffff:
        return b'\xfe%s' % struct.pack('<L', i)
    return b'\xff%s' % struct.pack('<Q', i)


def var_int_to_int(data):
    """
    Convert variable integer to integer

    :param data: bytes variable integer.
    :return: integer.
    """
    if data[0] == 0xfd:
        return struct.unpack('<H', data[1:3])[0]
    elif data[0] == 0xfe:
        return struct.unpack('<L', data[1:5])[0]
    elif data[0] == 0xff:
        return struct.unpack('<Q', data[1:9])[0]
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
    return b"".join((l, stream.read(get_var_int_len(l) - 1)))


def read_var_list(stream, data_type):
    """
    Read variable integer list from io.BytesIO stream to bytes

    :param stream: io.BytesIO stream.
    :param data_type: list data type.
    :return: list of data_type.
    """
    count = var_int_to_int(read_var_int(stream))
    return [data_type.deserialize(stream) for i in range(count)]

# compressed integer


def int_to_c_int(n, base_bytes=1):
    """
    Convert integer to compresed integer

    :param n: integer.
    :param base_bytes: len of bytes base from which start compression.
    :return: bytes.
    """
    if n == 0:
        return b'\x00' * base_bytes
    else:
        l = n.bit_length() + 1
    min_bits = base_bytes * 8 - 1
    if l <= min_bits + 1:
        return n.to_bytes(base_bytes, byteorder="big")
    prefix = 0
    payload_bytes = math.ceil((l)/8) - base_bytes
    extra_bytes = int(math.ceil((l+payload_bytes)/8) - base_bytes)
    for i in range(extra_bytes):
        prefix += 2 ** i
    if l < base_bytes * 8:
        l = base_bytes * 8
    prefix = prefix << l
    if prefix.bit_length() % 8:
        prefix = prefix << 8 - prefix.bit_length() % 8
    n ^= prefix
    return n.to_bytes(math.ceil(n.bit_length()/8), byteorder="big")


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
    n = int.from_bytes(b[:byte_length+base_bytes], byteorder="big")
    if byte_length:
        return n & ((1 << (byte_length+base_bytes) * 8 - byte_length) - 1)
    return n


def c_int_len(n, base_bytes=1):
    """
    Get length of compressed integer from integer value

    :param n: bytes.
    :param base_bytes: len of bytes base from which start compression.
    :return: integer.
    """
    if n == 0:
        return 1
    l = n.bit_length() + 1
    min_bits = base_bytes * 8 - 1
    if l <= min_bits + 1:
        return 1
    payload_bytes = math.ceil((l)/8) - base_bytes
    return int(math.ceil((l+payload_bytes)/8))


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
    s = struct.pack(b">I", bn_bytes(v, have_ext))
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
    v_len = struct.unpack(b">I", s_size)[0]
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
    # if r:
    r = r[::-1]         # reverse string, converting BE->LE
    # else: r=b'\x00'
    return r


def bn2vch(v):
    return bytes(mpi2vch(bn2mpi(v)))


def vch2mpi(s):
    r = struct.pack(b">I", len(s))   # size
    r += s[::-1]            # reverse string, converting LE->BE
    return r


def vch2bn(s):
    return mpi2bn(vch2mpi(s))


def i2b(i): return bn2vch(i)


def b2i(b): return vch2bn(b)


def get_stream(stream):
    if type(stream) != io.BytesIO:
        if type(stream) == str:
            stream = bytes.fromhex(stream)
        if type(stream) == bytes:
            stream = io.BytesIO(stream)
        else:
            raise TypeError
    return stream

