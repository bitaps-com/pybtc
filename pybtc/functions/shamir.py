import random
import time

def _precompute_gf256_exp_log():
    exp = [0 for i in range(255)]
    log = [0 for i in range(256)]
    poly = 1
    for i in range(255):
        exp[i] = poly
        log[poly] = i
        # Multiply poly by the polynomial x + 1.
        poly = (poly << 1) ^ poly
        # Reduce poly by x^8 + x^4 + x^3 + x + 1.
        if poly & 0x100:
            poly ^= 0x11B

    return exp, log

EXP_TABLE, LOG_TABLE = _precompute_gf256_exp_log()


def _gf256_mul(a, b):
    if a == 0 or b == 0:
        return 0
    return EXP_TABLE[ (LOG_TABLE[a] + LOG_TABLE[b]) % 255 ]

def _gf256_pow(a, b):
    if b == 0:
        return 1
    if a == 0:
        return 0
    c = a
    for i in range(b - 1):
        c = _gf256_mul(c,a)
    return c

def _gf256_add(a, b):
    return a ^ b

def _gf256_sub(a, b):
    return a ^ b

def _gf256_inverse(a):
    if a == 0:
        raise ZeroDivisionError()
    return EXP_TABLE[ (-LOG_TABLE[a]) % 255 ]

def _gf256_div(a, b):
    if b == 0:
        raise ZeroDivisionError()
    if a == 0:
        return 0
    r = _gf256_mul(a, _gf256_inverse(b))
    assert a == _gf256_mul(r, b)
    return r


def _fn(x, q):
    r = 0
    for i, a in enumerate(q):
        r = _gf256_add(r, _gf256_mul(a,_gf256_pow(x,i)))
    return r

def _interpolation(points, x=0):
    k = len(points)
    if k < 2:
        raise Exception("Minimum 2 points required")

    points = sorted(points, key=lambda z: z[0])

    p_x = 0
    for j in range(k):
        p_j_x  = 1
        for m in range(k):

            if m == j:
                continue
            a =  _gf256_sub(x, points[m][0])
            b =  _gf256_sub(points[j][0], points[m][0])
            c = _gf256_div(a, b)
            p_j_x = _gf256_mul(p_j_x, c)

        p_j_x = _gf256_mul( points[j][1], p_j_x)
        p_x  = _gf256_add(p_x , p_j_x)


    return p_x

def split_secret(threshold, total,  secret, index_bits=8):
    if not isinstance(secret, bytes):
        raise TypeError("Secret as byte string required")
    if threshold > 255:
        raise ValueError("threshold <= 255")
    if total > 255:
        raise ValueError("total shares <= 255")
    index_max = 2 ** index_bits - 1
    if total > index_max:
        raise ValueError("index bits is to low")

    shares = dict()
    shares_indexes = []


    while len(shares) != total:
        q = random.SystemRandom().randint(1, index_max)
        if q in shares:
            continue
        shares_indexes.append(q)
        shares[q] = b""


    for b in secret:
        q = [b]
        for i in range(threshold - 1):
            a = random.SystemRandom().randint(0, 255)
            i = int((time.time() % 0.0001) * 1000000) + 1
            q.append((a * i) % 255)

        for z in shares_indexes:
            shares[z] += bytes([_fn(z, q)])

    return shares

def restore_secret(shares):
    secret = b""
    share_length = None
    for share in shares:
        if share < 1 or share > 255:
            raise Exception("Invalid share index %s" % share)
    for share in shares.values():
        if share_length is None:
            share_length = len(share)
        if share_length != len(share) or share_length == 0:
            raise Exception("Invalid shares")

    for i in range(share_length):
        secret += bytes([_interpolation([(z, shares[z][i]) for z in  shares])])
    return secret
