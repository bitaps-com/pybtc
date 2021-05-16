from pybtc.functions.tools import s2rh
from pybtc.functions.tools import bytes_from_hex
from pybtc.functions.hash import ripemd160
from pybtc.functions.hash import sha3_256
from pybtc.functions.hash import hash160
from pybtc.functions.hash import siphash
from pybtc.functions.hash import murmurhash3
from pybtc.functions.hash import sha256
from pybtc.functions.hash import double_sha256
from pybtc.functions.hash import hmac_sha512


def test_ripemd160():
    assert ripemd160(b"test ripemd160").hex() == "45b17861a7defaac439f740d890f3dac4813cc37";
    assert ripemd160(b"test ripemd160".hex(), hex=True) == "45b17861a7defaac439f740d890f3dac4813cc37";

def test_sha3_256():
    assert sha3_256(bytes_from_hex("0000002040dee9142842cfd14796055fc8f16e48454b3"
                                   "1e1c1f34c69be4834f40b000000f2e8d5499863e98272"
                                   "006d82dab93645902a255b279b0e98add955f66b5b9b3"
                                   "cc7f1195e82670f1d9bc3ab00")) == s2rh("0000000b1ab864338f2ac7fd9d6b833b"
                                                                         "e3a113031f09c30e9c944c161635e0db")
    assert sha3_256("0000002040dee9142842cfd14796055fc8f16e48454b3"
                    "1e1c1f34c69be4834f40b000000f2e8d5499863e98272"
                    "006d82dab93645902a255b279b0e98add955f66b5b9b3"
                    "cc7f1195e82670f1d9bc3ab00") == s2rh("0000000b1ab864338f2ac7fd9d6b833b"
                                                         "e3a113031f09c30e9c944c161635e0db")

def test_hash160():
    assert hash160("03b635dbdc16dbdf4bb9cf5b55e7d03e514fb04dcef34208155c7d3ec88e9045f4").hex() == \
           "a307d67484911deee457779b17505cedd20e1fe9"
    assert hash160("03b635dbdc16dbdf4bb9cf5b55e7d03e514fb04dcef34208155c7d3ec88e9045f4", True)== \
           "a307d67484911deee457779b17505cedd20e1fe9"
    assert hash160(bytes_from_hex("03b635dbdc16dbdf4bb9cf5b55e7d03e514fb04dcef34208155c7d3ec88e9045f4")).hex() == \
           "a307d67484911deee457779b17505cedd20e1fe9"


def test_siphash():
    assert siphash(s2rh("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100").hex(),
                   v_0=0x0706050403020100, v_1=0x0F0E0D0C0B0A0908) == 0x7127512f72f27cce
    assert siphash(s2rh("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100"),
                   v_0=0x0706050403020100, v_1=0x0F0E0D0C0B0A0908) == 0x7127512f72f27cce
    assert siphash(b"", v_0=0x0706050403020100, v_1=0x0F0E0D0C0B0A0908) == 0x726fdb47dd0e0e31
    assert siphash(b"\x00", v_0=0x0706050403020100, v_1=0x0F0E0D0C0B0A0908) == 0x74f839c593dc67fd
    assert siphash(b'\x00\x01\x02\x03\x04\x05\x06\x07', v_0=0x0706050403020100, v_1=0x0F0E0D0C0B0A0908) == \
           0x93f5f5799a932462
    assert siphash(b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f',
                   v_0=0x0706050403020100, v_1=0x0F0E0D0C0B0A0908) == 0x3f2acc7f57c29bdb

def test_murmurhash3():
    assert murmurhash3(0, "") == 0
    assert murmurhash3(1, "") == 0x514E28B7
    assert murmurhash3(0xffffffff, "") == 0x81F16F39
    assert murmurhash3(0, b"\x00\x00\x00\x00") == 0x2362F9DE
    assert murmurhash3(0, b"\x00\x00\x00\x00".hex()) == 0x2362F9DE
    assert murmurhash3(0x9747b28c, b"aaaa".hex()) == 0x5A97808A
    assert murmurhash3(0x9747b28c, b"aa") == 0x5D211726
    assert murmurhash3(0x9747b28c, b"a") == 0x7FA09EA6
    assert murmurhash3(0x9747b28c, b"abcd") == 0xF0478627
    assert murmurhash3(0x9747b28c, b"abc") == 0xC84A62DD
    assert murmurhash3(0x9747b28c, b"ab") == 0x74875592
    assert murmurhash3(0x9747b28c, b"a") == 0x7FA09EA6
    assert murmurhash3(0x9747b28c, b"Hello, world!") == 0x24884CBA

def test_sha256():
    assert sha256(b"", hex=True) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert sha256(b"abc", hex=True) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert sha256(b"a" * 1000000, hex=False).hex() == "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
    assert sha256("de188941a3375d3a8a061e67576e926d", hex=True) == "067c531269735ca7f541fdaca8f0dc76" \
                                                                   "305d3cada140f89372a410fe5eff6e4d"
    assert sha256("de188941a3375d3a8a061e67576e926d"
                  "c71a7fa3f0cceb97452b4d3227965f9e"
                  "a8cc75076d9fb9c5417aa5cb30fc2219"
                  "8b34982dbb629e", hex=True) == "038051e9c324393bd1ca1978dd0952c2aa3742ca4f1bd5cd4611cea83892d382"

def test_double_sha256():
    assert double_sha256(b"", hex=True) == "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"
    assert double_sha256(b"abc", hex=True) == "4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358"
    assert double_sha256(b"a" * 1000000, hex=False).hex() == "80d1189477563e1b5206b2749f1afe48" \
                                                             "07e5705e8bd77887a60187a712156688"
    assert double_sha256("de188941a3375d3a8a061e67576e926d", hex=True) == "2182d3fe9882fd597d25daf6a85e3a57" \
                                                                          "4e5a9861dbc75c13ce3f47fe98572246"
    assert double_sha256("de188941a3375d3a8a061e67576e926d"
                         "c71a7fa3f0cceb97452b4d3227965f9e"
                         "a8cc75076d9fb9c5417aa5cb30fc2219"
                         "8b34982dbb629e", hex=True) == "3b4666a5643de038930566a5930713e6" \
                                                        "5d72888d3f51e20f9545329620485b03"

def test_hmac_sha512():
    assert hmac_sha512("4a656665",
                       "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
                       hex=True) == "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554" \
                                    "9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"

    assert hmac_sha512("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                       "4869205468657265",
                       hex=True) == "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde" \
                                    "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
    assert hmac_sha512("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                       "4869205468657265",
                       hex=False).hex() == "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde" \
                                           "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
    assert hmac_sha512(bytes_from_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                       bytes_from_hex("dddddddddddddddddddddddddddddddddddddddd"
                                      "dddddddddddddddddddddddddddddddddddddddd"
                                      "dddddddddddddddddddd"),
                       hex=False).hex() == "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39" \
                                           "bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb"
    assert hmac_sha512(bytes_from_hex("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c"),
                       "Test With Truncation", encoding="utf8",
                       hex=False).hex() == "415fad6271580a531d4179bc891d87a650188707922a4fbb36663a1eb16da008" \
                                           "711c5b50ddd0fc235084eb9d3364a1454fb2ef67cd1d29fe6773068ea266e96b"
    assert hmac_sha512(bytes_from_hex("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c"),
                       "Test With Truncation",
                       hex=False).hex() == "415fad6271580a531d4179bc891d87a650188707922a4fbb36663a1eb16da008" \
                                           "711c5b50ddd0fc235084eb9d3364a1454fb2ef67cd1d29fe6773068ea266e96b"
    assert hmac_sha512(bytes_from_hex("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c"),
                       "Test With Truncation",
                       hex=False).hex() == "415fad6271580a531d4179bc891d87a650188707922a4fbb36663a1eb16da008" \
                                           "711c5b50ddd0fc235084eb9d3364a1454fb2ef67cd1d29fe6773068ea266e96b"

