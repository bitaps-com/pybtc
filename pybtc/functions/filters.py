import struct
import io
from pybtc.functions.tools import int_to_bytes
from  math import log, ceil
from pybtc.constants import LN2SQUARED, LN2
from pybtc.functions.tools import  map_into_range, int_to_var_int
from pybtc.functions.hash import siphash, murmurhash3
from _bitarray import _bitarray

class bitarray(_bitarray):
    pass


from collections import deque

_BIT_MASK = bytearray([0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80])



def create_bloom_filter(n_elements, n_fp_rate, max_hash_func=50, max_bit_size=36000 * 8):
    # max_hash_func=50
    # max_bit_size=36000 * 8
    # bitcoin protocol default values
    # 20,000 items with fp rate < 0.1% or 10,000 items and <0.0001%

    l = -1 / LN2SQUARED * n_elements * log(n_fp_rate)
    if max_bit_size and l > max_bit_size:
        l = max_bit_size
    filter = bytearray(ceil(l/8))
    hash_func_count = int(min(l / n_elements * LN2, max_hash_func))
    return filter, hash_func_count

def insert_to_bloom_filter(filter, elem, hash_func_count, n_tweak = 0,  max_hash_func=50):
    fl = len(filter)
    if fl == 1 and filter[0] == 0xff: return

    for i in range(0, min(hash_func_count, max_hash_func)):
        n_index = murmurhash3(((i * 0xFBA4C795) + n_tweak) & 0xFFFFFFFF, elem) % (fl * 8)
        filter[n_index >> 3] |= _BIT_MASK[7 & n_index]
    return filter

def contains_in_bloom_filter(filter, elem, hash_func_count, n_tweak = 0,  max_hash_func=50):
    fl = len(filter)
    if fl == 1 and filter[0] == 0xff: return True

    for i in range(0, min(hash_func_count, max_hash_func)):
        n_index = murmurhash3(((i * 0xFBA4C795) + n_tweak) & 0xFFFFFFFF, elem) % (fl * 8)
        if not (filter[n_index >> 3] & _BIT_MASK[7 & n_index]): return False
    return True



def create_gcs(elements, M=784931, P=19, v_0=0, v_1=0, hashed=False, hex=False):
    # M=784931
    # P=19
    # BIP 158  constant values
    # v_0, v_1 - randomization vectors for siphash

    N = len(elements)

    if N >= 4294967296 or M >= 4294967296:
        raise TypeError("elements count MUST be <2^32 and M MUST be <2^32")

    gcs_filter = bitarray(endian='big')

    last = 0
    if not hashed:
        elements = [map_into_range(siphash(e, v_0=v_0, v_1=v_1), N * M) for e in elements]

    for value in  sorted(elements):
        delta = value - last
        q, r = delta >> P, delta & ((1 << P) - 1)

        while q:
            gcs_filter.append(True)
            q -= 1

        gcs_filter.append(False)

        c = P - 1
        while c >= 0:
            gcs_filter.append(bool(r & (1 << c)))
            c -= 1

        last = value

    f = gcs_filter.tobytes()
    return f.hex() if hex else f


def decode_gcs(h, N, P=19):
    s = []
    last = 0
    gcs_filter = bitarray(endian='big')
    gcs_filter.frombytes(h)
    f = 0
    for i in range(N):
        q = 0
        r = 0

        while gcs_filter[f]:
            q += 1
            f += 1
        f += 1
        c = P - 1

        while c >= 0:
            r = r << 1
            if gcs_filter[f]:
                r += 1
            f += 1

            c -= 1

        delta = (q << P) + r
        last += delta
        s.append(last)

    return s

