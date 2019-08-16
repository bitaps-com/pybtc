import struct
import math
from pybtc.constants import *

_BIT_MASK = bytearray([0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80])


def _ROTL32(x, r):
    return ((x << r) & 0xFFFFFFFF) | (x >> (32 - r))


def murmur_hash3(nHashSeed, vDataToHash):
    """MurmurHash3 (x86_32)
    Used for bloom filters. See http://code.google.com/p/smhasher/source/browse/trunk/MurmurHash3.cpp
    """

    assert nHashSeed <= 0xFFFFFFFF

    h1 = nHashSeed
    c1 = 0xcc9e2d51
    c2 = 0x1b873593

    # body
    i = 0
    while (i < len(vDataToHash) - len(vDataToHash) % 4
           and len(vDataToHash) - i >= 4):

        k1 = struct.unpack(b"<L", vDataToHash[i:i+4])[0]

        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = _ROTL32(k1, 15)
        k1 = (k1 * c2) & 0xFFFFFFFF

        h1 ^= k1
        h1 = _ROTL32(h1, 13)
        h1 = (((h1*5) & 0xFFFFFFFF) + 0xe6546b64) & 0xFFFFFFFF

        i += 4


    k1 = 0
    j = (len(vDataToHash) // 4) * 4
    bord = lambda x: x
    if len(vDataToHash) & 3 >= 3:
        k1 ^= bord(vDataToHash[j+2]) << 16
    if len(vDataToHash) & 3 >= 2:
        k1 ^= bord(vDataToHash[j+1]) << 8
    if len(vDataToHash) & 3 >= 1:
        k1 ^= bord(vDataToHash[j])

    k1 &= 0xFFFFFFFF
    k1 = (k1 * c1) & 0xFFFFFFFF
    k1 = _ROTL32(k1, 15)
    k1 = (k1 * c2) & 0xFFFFFFFF
    h1 ^= k1

    # finalization
    h1 ^= len(vDataToHash) & 0xFFFFFFFF
    h1 ^= (h1 & 0xFFFFFFFF) >> 16
    h1 *= 0x85ebca6b
    h1 ^= (h1 & 0xFFFFFFFF) >> 13
    h1 *= 0xc2b2ae35
    h1 ^= (h1 & 0xFFFFFFFF) >> 16

    return h1 & 0xFFFFFFFF


def create_bloom_filter(n_elements, n_fp_rate):
    return bytearray(int(min(-1 / LN2SQUARED * n_elements * math.log(n_fp_rate), MAX_BLOOM_FILTER_SIZE * 8) / 8))

def insert_to_bloom_filter(filter, elem, max_elements_count, n_tweak = 0):
    fl = len(filter)
    if fl == 1 and filter[0] == 0xff: return

    for i in range(0, int(min(fl * 8 / max_elements_count * LN2, MAX_HASH_FUNCS))):
        n_index = murmur_hash3(((i * 0xFBA4C795) + n_tweak) & 0xFFFFFFFF, elem) % (fl * 8)
        filter[n_index >> 3] |= _BIT_MASK[7 & n_index]
    return filter

def contains_in_bloom_filter(filter, elem, max_elements_count, n_tweak = 0):
    fl = len(filter)
    if fl == 1 and filter[0] == 0xff: return

    for i in range(0, int(min(fl * 8 / max_elements_count * LN2, MAX_HASH_FUNCS))):
        n_index = murmur_hash3(((i * 0xFBA4C795) + n_tweak) & 0xFFFFFFFF, elem) % (fl * 8)
        if not (filter[n_index >> 3] & _BIT_MASK[7 & n_index]):
            return False
    return True


