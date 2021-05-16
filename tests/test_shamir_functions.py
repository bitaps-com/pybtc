import pytest
import random
from pybtc.functions import shamir


def test_gf256_math():
    for i in range(1, 256):
        assert 1 == shamir._gf256_mul(i, shamir._gf256_inverse(i))
    for i in range(0, 256):
        for j in range(1, 256):
            a = shamir._gf256_div(i, j)
            b = shamir._gf256_mul(a, j)
            assert i == b

            a = shamir._gf256_add(i, j)
            b = shamir._gf256_sub(a, j)
            assert i == b
    k = 2
    for i in range(2, 256):
        a = shamir._gf256_pow(k, i)
        b = k
        for j in range(i - 1):
            b = shamir._gf256_mul(b, k)
        assert b == a
    assert shamir._gf256_pow(0, 0) == 1
    assert shamir._gf256_pow(0, 1) == 0

    with pytest.raises(ZeroDivisionError):
        shamir._gf256_inverse(0)

    with pytest.raises(ZeroDivisionError):
        shamir._gf256_div(1, 0)

def test_secret_spliting():
    secret = b"w"
    for i in range(100):
        shares = shamir.split_secret(5,5, secret)
        s = shamir.restore_secret(shares)
        assert  s == secret

    secret = b"w36575hrhgdivgsidyufgiuhgvsufgoyirsgfiusgrf"
    for i in range(100):
        shares = shamir.split_secret(5,5, secret)
        s = shamir.restore_secret(shares)
        assert  s == secret

    for i in range(2, 20):
        shares = shamir.split_secret(i, i, secret)
        s = shamir.restore_secret(shares)
        assert s == secret

    for i in range(2, 20):
        k = random.randint(i, i + 10)
        shares = shamir.split_secret(i, k, secret)
        keys = [q for q in shares]
        b = dict()
        while len(b) < i:
            q = random.randint(0, len(keys)-1)
            q = keys[q]

            b[q] = shares[q]
        s = shamir.restore_secret(b)
        assert s ==secret

    with pytest.raises(TypeError):
        shamir.split_secret(5,5, "ee11")
    with pytest.raises(ValueError):
        shamir.split_secret(905,5, secret)
    with pytest.raises(ValueError):
        shamir.split_secret(5,905, secret)

    shares = shamir.split_secret(5, 5, secret)
    shares[1] = b"55"
    with pytest.raises(Exception):
        shamir.restore_secret(shares)
    with pytest.raises(Exception):
        shamir.restore_secret({0:b"33", 1:b"34"})
    with pytest.raises(Exception):
        shamir.split_secret(20, 20, secret, index_bits = 2)




def test__interpolation():
    with pytest.raises(Exception):
        shamir._interpolation([])
