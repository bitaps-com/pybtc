import struct
from  math import log, ceil
from pybtc.constants import *
from pybtc.crypto import murmurhash3

_BIT_MASK = bytearray([0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80])

def create_bloom_filter(n_elements, n_fp_rate):
    l = -1 / LN2SQUARED * n_elements * log(n_fp_rate)
    filter = bytearray(ceil(l/8))
    hash_func_count = int(min(l / n_elements * LN2, MAX_HASH_FUNCS))
    return filter, hash_func_count


def insert_to_bloom_filter(filter, elem, hash_func_count, n_tweak = 0):
    fl = len(filter)
    if fl == 1 and filter[0] == 0xff: return

    for i in range(0, min(hash_func_count, MAX_HASH_FUNCS)):
        n_index = murmurhash3(((i * 0xFBA4C795) + n_tweak) & 0xFFFFFFFF, elem) % (fl * 8)
        filter[n_index >> 3] |= _BIT_MASK[7 & n_index]
    return filter

def contains_in_bloom_filter(filter, elem, hash_func_count, n_tweak = 0):
    fl = len(filter)
    if fl == 1 and filter[0] == 0xff: return True

    for i in range(0, min(hash_func_count, MAX_HASH_FUNCS)):
        n_index = murmurhash3(((i * 0xFBA4C795) + n_tweak) & 0xFFFFFFFF, elem) % (fl * 8)
        if not (filter[n_index >> 3] & _BIT_MASK[7 & n_index]): return False
    return True
