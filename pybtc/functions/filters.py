import struct
import io
from pybtc.functions.tools import int_to_var_int, read_var_int, var_int_to_int
from  math import log, ceil, floor, log2
from pybtc.constants import LN2SQUARED, LN2
from pybtc.functions.tools import  map_into_range, get_stream
from pybtc.functions.hash import siphash, murmurhash3
from _bitarray import _bitarray
from heapq import heappush, heappop

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


def create_gcs_filter(elements, N=None, M=784931, P=19, v_0=0, v_1=0, hex=False):
    # M=784931
    # P=19
    # BIP 158  constants
    # v_0, v_1 - randomization vectors for siphash

    if N is None:
        N = len(elements)
    if N >= 4294967296 or M >= 4294967296:
        raise TypeError("elements count MUST be <2^32 and M MUST be <2^32")

    elements = [map_into_range(siphash(e, v_0=v_0, v_1=v_1), N * M) for e in elements]
    f = encode_gcs(elements, P)

    return f.hex() if hex else f

def encode_deltas(elements):
    last = 0
    max_v = 0
    deltas = deque()
    for value in elements:
        d = value - last
        last = value
        deltas.append(d)
        if max_v < d:
            max_v = d
    return deltas, max_v


def encode_gcs(elements, P = None, sort = True, deltas = True):
    gcs_filter = bitarray()
    gcs_filter_append = gcs_filter.append

    if len(elements) == 0:
        return b""

    if sort:
        elements = sorted(elements)
    if P is None:
        if deltas:
            last = 0

            if len(elements) < 2:
                d_max = elements[0]
            else:
                d_max = 0
                new_elements = deque()
                for value in elements:
                    d = value - last
                    new_elements.append(d)
                    if last and d_max < d:
                        d_max = d
                    last = value

                deltas = False
                elements = new_elements
        else:
            d_max = max(elements)
        if not sort:
            mc = sorted(elements)[len(elements) // 2] # median high
        else:
            mc = elements[len(elements) // 2] # median high
        d_max = d_max if d_max > 1 else 2
        mc = mc if mc > 1 else 2

        P = (floor(log2((mc / 1.497137))) + floor(log2((d_max / 1.497137)))) >> 1

        if P < 1:
            P = 1

    last = 0
    for value in elements:
        if deltas:
            e = value - last
            last = value
        else:
            e = value
        q, r = e >> P, e & ((1 << P) - 1)

        while q:
            gcs_filter_append(True)
            q -= 1

        gcs_filter_append(False)

        c = P - 1
        while c >= 0:
            gcs_filter_append(bool(r & (1 << c)))
            c -= 1

    return int_to_var_int(len(elements)) + int_to_var_int(P) + gcs_filter.tobytes()


def decode_gcs(h):
    stream = get_stream(h)
    L = var_int_to_int(read_var_int(stream))
    P = var_int_to_int(read_var_int(stream))
    s = deque()
    s_append = s.append
    last = 0
    gcs_filter = bitarray(endian='big')
    gcs_filter.frombytes(stream.read())

    f = 0
    for i in range(L):
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
        s_append(last)
    return s



class Node(object):
    def __init__(self):
        self.child = [None, None]
        self.symbol = None
        self.freq = None

    def __lt__(self, other):
        return self.freq < other.freq

def huffman_tree(freq):
    minheap = []
    for c in sorted(freq):
        nd = Node()
        nd.symbol = c
        nd.freq = freq[c]
        heappush(minheap, nd)

    while len(minheap) > 1:
        r = heappop(minheap)
        l = heappop(minheap)

        parent = Node()
        parent.child = [l, r]
        parent.freq = l.freq + r.freq
        heappush(minheap, parent)

    return minheap[0]

def huffman_code(tree):
    result = {}

    def traverse(nd, prefix=bitarray()):
        if nd.symbol is None: # parent, so traverse each of the children
            for i in range(2):
                traverse(nd.child[i], prefix + bitarray([i]))
        else: # leaf
            if prefix == bitarray():
                prefix = bitarray("0")
            result[nd.symbol] = prefix

    traverse(tree)

    return result

def huffman_freq_normalize(freq):
    r = dict()
    for i in freq:
        try:
            r[freq[i]].append(i)
        except:
            r[freq[i]] = [i]

    codes = deque()
    for i in sorted(r.keys()):
        for e in sorted(r[i]):
            codes.append(e)

    nfreq = dict()
    for i in range(len(codes)):
        nfreq[codes[i]] = i + 1

    return nfreq, codes


def encode_huffman(elements):
    if elements:
        map_freq = dict()
        for value in  elements:
            try:
                map_freq[value] += 1
            except:
                map_freq[value] = 1
        bitstr = bitarray()
        nfreq, code_table = huffman_freq_normalize(map_freq)
        codes = huffman_code(huffman_tree(nfreq))
        bitstr.encode(codes, elements)

        code_table_string = int_to_var_int(len(code_table))
        for code in code_table:
            code_table_string += int_to_var_int(code)
        h = bitstr.tobytes()
        delta_bit_length = 8 * len(h) -  bitstr.length()
        return b"".join((code_table_string,
                         int_to_var_int(len(h)),
                         int_to_var_int(delta_bit_length),
                         h))
    return b""


def decode_huffman(h):
    if h:
        stream = get_stream(h)
        c = var_int_to_int(read_var_int(stream))
        freq = dict()
        for i in range(c):
             key = var_int_to_int(read_var_int(stream))
             freq[key] = i + 1
        codes = huffman_code(huffman_tree(freq))

        l = var_int_to_int(read_var_int(stream))
        delta_bit_length = var_int_to_int(read_var_int(stream))
        d = bitarray()
        d.frombytes(stream.read(l))
        while d.length() > (l  * 8 - delta_bit_length):
            d.pop()
        return d.decode(codes)
    return []



def encode_dhcs(elements, min_bits_threshold=20):
    # Delta-Hoffman coded set
    data_sequence = bitarray()
    data_sequence_append = data_sequence.append

    deltas_bits = deque()
    deltas_bits_map_freq = dict()
    last = 0

    for value in  sorted(elements):
        delta =  value - last

        bits = delta.bit_length()
        if bits < min_bits_threshold:
            bits =  min_bits_threshold

        deltas_bits.append(bits)

        try:
            deltas_bits_map_freq[bits] += 1
        except:
            deltas_bits_map_freq[bits] = 1

        while bits > 0:
            data_sequence_append(delta & (1 << (bits - 1)))
            bits -= 1
        last = value

    # huffman encode round 1
    # encode bits length sequence to byte string
    codes_round_1 = huffman_code(huffman_tree(deltas_bits_map_freq))
    r = bitarray()
    r.encode(codes_round_1, deltas_bits)
    bits_sequence = r.tobytes()
    bits_sequnce_len_round_1 = r.length()

    # huffman encode round 2
    # encode byte string
    deltas_bits = deque()
    deltas_bits_map_freq = dict()
    for i in bits_sequence:
        b = i >> 4
        c = i & 0b1111
        deltas_bits.append(b)
        try:
            deltas_bits_map_freq[b] += 1
        except:
            deltas_bits_map_freq[b] = 1

        deltas_bits.append(c)
        try:
            deltas_bits_map_freq[c] += 1
        except:
            deltas_bits_map_freq[c] = 1

    codes_round_2 = huffman_code(huffman_tree(deltas_bits_map_freq))
    r = bitarray()
    r.encode(codes_round_2, deltas_bits)
    bits_sequnce_len_round_2 = r.length()
    bits_sequence = r.tobytes()


    code_table_1 = int_to_var_int(len(codes_round_1))
    for code in codes_round_1:
        code_table_1 += int_to_var_int(code)
        code_table_1 += int_to_var_int(codes_round_1[code].length())
        code_table_1 += b"".join([bytes([i]) for i in codes_round_1[code].tolist()])

    code_table_2 = int_to_var_int(len(codes_round_2))
    for code in codes_round_2:
        code_table_2 += int_to_var_int(code)
        code_table_2 += int_to_var_int(codes_round_2[code].length())
        code_table_2 += b"".join([bytes([i]) for i in codes_round_2[code].tolist()])


    d_filter_len = data_sequence.length()
    d_filter_string = data_sequence.tobytes()

    return  b"".join((code_table_1,
                      code_table_2,
                      int_to_var_int(bits_sequnce_len_round_1),
                      int_to_var_int(bits_sequnce_len_round_2),
                      bits_sequence,
                      int_to_var_int(d_filter_len),
                      d_filter_string))



def decode_dhcs(h):
    # Delta-Hoffman coded set
    stream = get_stream(h)

    # read code_table_1
    c = var_int_to_int(read_var_int(stream))
    code_table_1 = dict()
    for i in range(c):
        key = var_int_to_int(read_var_int(stream))
        l = var_int_to_int(read_var_int(stream))
        code =  bitarray([bool(k) for k in stream.read(l)])
        code_table_1[key] = code

    # read code_table_2
    c = var_int_to_int(read_var_int(stream))
    code_table_2 = dict()
    for i in range(c):
        key = var_int_to_int(read_var_int(stream))
        l = var_int_to_int(read_var_int(stream))
        code =  bitarray([bool(k) for k in stream.read(l)])
        code_table_2[key] = code

    # read compressed deltas
    deltas_bits_len_1 = var_int_to_int(read_var_int(stream))
    deltas_bits_len_2 = var_int_to_int(read_var_int(stream))
    deltas_byte_len = deltas_bits_len_2 // 8 + int(bool(deltas_bits_len_2 % 8))

    r = stream.read(deltas_byte_len)
    deltas = bitarray()
    deltas.frombytes(r)

    while deltas.length() > deltas_bits_len_2:
        deltas.pop()

    # Huffman decode round 1
    r = deltas.decode(code_table_2)
    deltas_string = bytearray()
    for i in range(int(len(r)/2)):
        deltas_string += bytes([(r[i*2] << 4) + r[i*2 + 1]])

    # Huffman decode round 2
    r = bitarray()
    r.frombytes(bytes(deltas_string))

    while r.length() > deltas_bits_len_1:
        r.pop()

    deltas_bits = r.decode(code_table_1)


    d_filter_bit_len = var_int_to_int(read_var_int(stream))
    d_filter_byte_len = d_filter_bit_len // 8 + int(bool(d_filter_bit_len % 8))
    r = stream.read(d_filter_byte_len)

    d_filter = bitarray()
    d_filter.frombytes(r)

    while d_filter.length() > d_filter_bit_len:
        d_filter.pop()

    f = 0
    f_max = d_filter.length()
    decoded_set = set()
    last = 0

    for bits in deltas_bits:
        d = 0
        while bits  > 0 and f < f_max :
            bits -= 1
            d = d << 1
            if d_filter[f]:
                d += 1
            f += 1
        last += d
        decoded_set.add(last)

    return decoded_set
