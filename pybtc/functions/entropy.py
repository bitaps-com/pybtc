from pybtc.constants import *
import random
import math

def generate_entropy(strength=256, hex=True):
    """
    Generate 128-256 bits entropy bytes string

    :param int strength: entropy bits strength, by default is 256 bit.
    :param boolean hex: return HEX encoded string result flag, by default True.
    :return: HEX encoded or bytes entropy string.
    """
    if strength not in [128, 160, 192, 224, 256]:
        raise ValueError('strength should be one of the following [128, 160, 192, 224, 256]')
    c = 0
    while True:
        a = random.SystemRandom().randint(0, ECDSA_SEC256K1_ORDER)
        try:
            randomness_test(a)
            if a > ECDSA_SEC256K1_ORDER:
                raise Exception("ECDSA_SEC256K1_ORDER")
            break
        except:
            if c < 100:
                c += 1
                continue
            else:
                raise Exception("Entropy generator filed")
    h = a.to_bytes(32, byteorder="big")
    return h[:int(strength/8)] if not hex else h[:int(strength/8)].hex()

def ln_gamma(z):
    if z<0:
        return None
    x = GAMMA_TABLE_LN[0]
    i = len(GAMMA_TABLE_LN) - 1
    while i > 0:
        x += GAMMA_TABLE_LN[i] / (z + i)
        i -= 1
    t = z + GAMMA_NUM_LN + 0.5
    return 0.5 * math.log(2 * math.pi) + (z + 0.5) * math.log(t) - t + math.log(x) - math.log(z)

def igam(a, x):
    if x <= 0 or a <= 0:
        return 0.0
    if x > 1.0 and x > a:
        return 1.0 - igamc(a, x)
    ax = a * math.log(x) - x - ln_gamma(a)

    if ax < -MAXLOG:
        return 0.0
    ax = math.exp(ax)
    r = a
    c = 1.0
    ans = 1.0
    while True:
        r += 1.0
        c *= x / r
        ans += c
        if not c / ans > MACHEP:
            break
    return ans * ax / a

def igamc(a, x):
    if x <= 0 or a <= 0:
        return 1.0
    if x < 1.0 or x < a:
        return 1.0 - igam(a, x)
    big = 4.503599627370496e15
    biginv = 2.22044604925031308085e-16
    ax = a * math.log(x) - x - ln_gamma(a)
    if ax < - MAXLOG:
        return 0.0
    ax = math.exp(ax)
    y = 1.0 - a
    z = x + y + 1.0
    c = 0.0
    pkm2 = 1.0
    qkm2 = x
    pkm1 = x + 1.0
    qkm1 = z * x
    ans = pkm1 / qkm1

    while True:
        c += 1.0
        y += 1.0
        z += 2.0
        yc = y * c
        pk = pkm1 * z - pkm2 * yc
        qk = qkm1 * z - qkm2 * yc
        if qk != 0:
            r = pk / qk
            t = abs((ans - r) / r)
            ans = r
        else:
            t = 1.0

        pkm2 = pkm1
        pkm1 = pk
        qkm2 = qkm1
        qkm1 = qk
        if abs(pk) > big:
            pkm2 *= biginv
            pkm1 *= biginv
            qkm2 *= biginv
            qkm1 *= biginv
        if not t > MACHEP:
            break
    return ans * ax

def randomness_test(b):
    # NIST SP 800-22 randomness tests
    # https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-22r1a.pdf
    s = bin(b)[2:].rjust(256, '0')

    # Frequency (Monobit) Test
    n = len(s)
    s_0 = s.count('0')
    s_1 = s.count('1')
    s_obs =abs(s_1 - s_0) / math.sqrt(2 * n)
    if  math.erfc(s_obs) < 0.01:
       raise Exception('Frequency (Monobit) Test failed.')

    # Runs Test
    pi = s_1 / n
    r = 2 / math.sqrt(n)
    if abs(pi - 0.5) > r:
        raise Exception('Runs Test failed.')
    v = 1
    for i in range(n-1):
        v += 0 if  (s[i] == s[i + 1]) else 1

    a = v - 2 * n * pi * (1 - pi)
    q = 2 * math.sqrt(2 * n) * pi * (1 - pi);

    if  math.erfc(abs(a) / q) < 0.01:
        raise Exception('Runs Test failed.')

    # Test for the Longest Run of Ones in a Block
    s = s[:256]
    blocks = [s[i:i + 8] for i in range(0, len(s), 8)]
    v = [0, 0, 0, 0]
    for block in blocks:
        if block == "":
            continue
        l = max(len(i) for i in block.split("0"))
        if l < 2:
            v[0] += 1
        elif l == 2:
            v[1] += 1
        elif l == 3:
            v[2] += 1
        else:
            v[3] += 1

    k = 3
    r = len(blocks)
    pi = [0.2148, 0.3672, 0.2305, 0.1875]
    x_sqrt = math.pow(v[0] - r * pi[0], 2) / (r * pi[0])
    x_sqrt += math.pow(v[1] - r * pi[1], 2) / (r * pi[1])
    x_sqrt += math.pow(v[2] - r * pi[2], 2) / (r * pi[2])
    x_sqrt += math.pow(v[3] - r * pi[3], 2) / (r * pi[3])

    if  (igamc(k / 2, x_sqrt / 2) < 0.01):
        raise Exception('Test for the Longest Run of Ones in a Block failed.')
