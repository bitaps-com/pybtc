from pybtc import *

def test_ripemd160():
    assert ripemd160(b"test ripemd160").hex() == "45b17861a7defaac439f740d890f3dac4813cc37";
    assert ripemd160(b"test ripemd160".hex(), hex=True) == "45b17861a7defaac439f740d890f3dac4813cc37";

def test_sha3_256():
    assert sha3_256(bytes_from_hex("0000002040dee9142842cfd14796055fc8f16e48454b3"
                                   "1e1c1f34c69be4834f40b000000f2e8d5499863e98272"
                                   "006d82dab93645902a255b279b0e98add955f66b5b9b3"
                                   "cc7f1195e82670f1d9bc3ab00")) == s2rh("0000000b1ab864338f2ac7fd9d6b833b"
                                                                         "e3a113031f09c30e9c944c161635e0db")

def test_double_sha256():
    assert double_sha256(b"test double sha256").hex() == \
           "1ab3067efb509c48bda198f48c473f034202537c28b7b4c3b2ab2c4bf4a95c8d"
    assert double_sha256(b"test double sha256", True) == \
           "1ab3067efb509c48bda198f48c473f034202537c28b7b4c3b2ab2c4bf4a95c8d"
    assert double_sha256(b"test double sha256".hex()).hex() == \
           "1ab3067efb509c48bda198f48c473f034202537c28b7b4c3b2ab2c4bf4a95c8d"

def test_hash160():
    assert double_sha256(b"test double sha256").hex() == \
           "1ab3067efb509c48bda198f48c473f034202537c28b7b4c3b2ab2c4bf4a95c8d"
    assert double_sha256(b"test double sha256", True) == \
           "1ab3067efb509c48bda198f48c473f034202537c28b7b4c3b2ab2c4bf4a95c8d"
    assert double_sha256(b"test double sha256".hex(), True) == \
           "1ab3067efb509c48bda198f48c473f034202537c28b7b4c3b2ab2c4bf4a95c8d"

def test_siphash():
    assert siphash(s2rh("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100"),
                   v_0=0x0706050403020100, v_1=0x0F0E0D0C0B0A0908) == 0x7127512f72f27cce
    assert siphash(b"", v_0=0x0706050403020100, v_1=0x0F0E0D0C0B0A0908) == 0x726fdb47dd0e0e31
    assert siphash(b"\x00", v_0=0x0706050403020100, v_1=0x0F0E0D0C0B0A0908) == 0x74f839c593dc67fd
    assert siphash(b'\x00\x01\x02\x03\x04\x05\x06\x07', v_0=0x0706050403020100, v_1=0x0F0E0D0C0B0A0908) == \
           0x93f5f5799a932462
    assert siphash(b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f',
                   v_0=0x0706050403020100, v_1=0x0F0E0D0C0B0A0908) == 0x3f2acc7f57c29bdb


