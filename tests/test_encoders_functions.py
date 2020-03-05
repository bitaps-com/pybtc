from pybtc.functions.encode import encode_base58
from pybtc.functions.encode import decode_base58
from pybtc.functions.encode import rebase_8_to_5
from pybtc.functions.encode import rebase_5_to_8
from pybtc.functions.encode import rebase_32_to_5
from pybtc.functions.encode import rebase_5_to_32
from pybtc.functions.encode import rebasebits
from pybtc.functions.encode import bech32_polymod
import pytest

def test_encode_base58():
    assert encode_base58("000002030405060708090a0b0c0d0e0f") == "11ju1bKJX8HGdT7YmKLi"
    assert encode_base58("") == ""
    assert encode_base58("00759d5f2b6d12712fef6f0f24c56804193e1aeac176c1faae") == \
           "1Bitapsw1aT8hkLXFtXwZQfHgNwNJEyJJ1"
    assert encode_base58("00759d5f2b6d12712fef6f0f24c56804193e1aeac1", checksum=True) == \
           "1Bitapsw1aT8hkLXFtXwZQfHgNwNJEyJJ1"


def test_decode_base58():
    assert decode_base58("") == b""
    assert decode_base58("1Bitapsw1aT8hkLXFtXwZQfHgNwNJEyJJ1", True) == \
           "00759d5f2b6d12712fef6f0f24c56804193e1aeac176c1faae"
    assert decode_base58("1Bitapsw1aT8hkLXFtXwZQfHgNwNJEyJJ1", False).hex() == \
           "00759d5f2b6d12712fef6f0f24c56804193e1aeac176c1faae"
    assert decode_base58("1Bitapsw1aT8hkLXFtXwZQfHgNwNJEyJJ1", checksum=True).hex() == \
           "00759d5f2b6d12712fef6f0f24c56804193e1aeac1"
    assert decode_base58("1Bitapsw1aT8hkLXFtXwZQfHgNwNJEyJJ1", verify_checksum=True).hex() == \
           "00759d5f2b6d12712fef6f0f24c56804193e1aeac1"

    with pytest.raises(Exception):
        decode_base58("1Bitapsw1aT8hkLXFtXwZQfHgNwNJEyJJ2", verify_checksum=True)
    with pytest.raises(Exception):
        decode_base58(876)

def test_rebase_bits():
    assert rebase_5_to_8(rebase_8_to_5(b"1234567890")) == b"1234567890"
    assert rebase_5_to_8(rebase_32_to_5(rebase_5_to_32(rebase_8_to_5(b"1234567890")))) == b"1234567890"
    assert rebase_5_to_8(rebase_32_to_5("xyerxdp4xcmnswfs")) == b"1234567890"
    with pytest.raises(Exception):
        rebasebits(b"0\xff1234567890", 5, 8)
    with pytest.raises(Exception):
        rebasebits(b"12345678901", 8, 5, False)
    assert rebase_5_to_8(rebase_8_to_5(b"12345678901")) == b"12345678901\x00"
    assert rebase_5_to_8(rebase_8_to_5(b"12345678901"), False) == b"12345678901"
    with pytest.raises(Exception):
        rebase_32_to_5("xyerxdp4xcmnswf§")

def test_bech32_polymod():
    assert bech32_polymod(b'\x03\x03\x00\x02\x03\x00\x17\x02' +
                          b'\x13\x11\x0e\x11\t\x15\x14\x1e\x0f' +
                          b'\x13\x1a\x03\x17\x0c\x1e\x1f\x0c' +
                          b'\x1e\x13\x1f\x0f\x05\x02\x01\x03' +
                          b'\x11\x18\x0b\x1d\x17\x00\x00\x00' +
                          b'\x00\x00\x00') ==246974674