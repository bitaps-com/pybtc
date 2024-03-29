from pybtc.functions.tools import *
import math
import pytest

def test_tools():
    assert s2rh_step4("1cc3689690a317e0d2da10532cdcf7e300bd4b07d031fd4d7088fbc8d48ee8c2") == \
        bytes_from_hex("9668c31ce017a3905310dad2e3f7dc2c074bbd004dfd31d0c8fb8870c2e88ed4")

    assert bytes_needed(258) == 2
    assert bytes_needed(43) == 1
    assert int_to_bytes(43873) == b'\xaba'
    assert bytes_to_int(b'\xaba') == 43873

def test_variable_integer():
    for i in range(0, 0xfd):
        assert var_int_to_int((int_to_var_int(i))) == i
        assert var_int_len(i) == len(int_to_var_int(i))
        assert var_int_len(i) == 1
        assert get_var_int_len(int_to_var_int(i)) == 1
        assert read_var_int(get_stream(int_to_var_int(i))) == int_to_var_int(i)
    for i in range(0xfd, 0xfff):
        assert var_int_to_int((int_to_var_int(i))) == i
        assert var_int_len(i) == 3
        assert var_int_len(i) == len(int_to_var_int(i))
        assert get_var_int_len(int_to_var_int(i)) == 3
        assert read_var_int(get_stream(int_to_var_int(i))) == int_to_var_int(i)
    for i in range(0xfff0, 0xffff):
        assert var_int_to_int((int_to_var_int(i))) == i
        assert len(int_to_var_int(i)) == 3
        assert var_int_len(i) == len(int_to_var_int(i))
        assert get_var_int_len(int_to_var_int(i)) == 3
        assert read_var_int(get_stream(int_to_var_int(i))) == int_to_var_int(i)
    for i in range(0x10000, 0x10010):
        assert var_int_to_int((int_to_var_int(i))) == i
        assert len(int_to_var_int(i)) == 5
        assert var_int_len(i) == len(int_to_var_int(i))
        assert get_var_int_len(int_to_var_int(i)) == 5
        assert read_var_int(get_stream(int_to_var_int(i))) == int_to_var_int(i)
    for i in range(0xffffff00, 0xffffffff):
        assert var_int_to_int((int_to_var_int(i))) == i
        assert len(int_to_var_int(i)) == 5
        assert var_int_len(i) == len(int_to_var_int(i))
        assert get_var_int_len(int_to_var_int(i)) == 5
        assert read_var_int(get_stream(int_to_var_int(i))) == int_to_var_int(i)
    for i in range(0x100000000, 0x100001000):
        assert var_int_to_int((int_to_var_int(i))) == i
        assert len(int_to_var_int(i)) == 9
        assert var_int_len(i) == len(int_to_var_int(i))
        assert get_var_int_len(int_to_var_int(i)) == 9
        assert read_var_int(get_stream(int_to_var_int(i))) == int_to_var_int(i)
        
def test_compressed_integer():
    for i in range(126, 130):
        assert c_int_to_int((int_to_c_int(i))) == i
        assert c_int_len(i) == len(int_to_c_int(i))
    assert len(int_to_c_int(i)) == 2
    for i in range(16382, 16386):
        assert c_int_to_int((int_to_c_int(i))) == i
        assert c_int_len(i) == len(int_to_c_int(i))
    assert len(int_to_c_int(i)) == 3
    for i in range(2097149, 2097154):
        assert c_int_to_int((int_to_c_int(i))) == i
        assert c_int_len(i) == len(int_to_c_int(i))
    assert len(int_to_c_int(i)) == 4
    for i in range(268435454, 268435458):
        assert c_int_to_int((int_to_c_int(i))) == i
        assert c_int_len(i) == len(int_to_c_int(i))
    assert len(int_to_c_int(i)) == 5
    for i in range(34359738366, 34359738370):
        assert c_int_to_int((int_to_c_int(i))) == i
        assert c_int_len(i) == len(int_to_c_int(i))
    assert len(int_to_c_int(i)) == 6
    for i in range(4398046511102, 4398046511106):
        assert c_int_to_int((int_to_c_int(i))) == i
        assert c_int_len(i) == len(int_to_c_int(i))
    assert len(int_to_c_int(i)) == 7
    for i in range(562949953421310, 562949953421314):
        assert c_int_to_int((int_to_c_int(i))) == i
        assert c_int_len(i) == len(int_to_c_int(i))
    assert len(int_to_c_int(i)) == 8
    for i in range(72057594037927934, 72057594037927938):
        assert c_int_to_int((int_to_c_int(i))) == i
        assert c_int_len(i) == len(int_to_c_int(i))
    assert len(int_to_c_int(i)) == 9
    i = 16250249101024000000
    assert c_int_to_int((int_to_c_int(i))) == i
    assert c_int_len(i) == len(int_to_c_int(i))
    assert len(int_to_c_int(i)) == 10
    i = 1333870604623599278750
    assert c_int_to_int((int_to_c_int(i))) == i

    i = 0
    assert c_int_to_int((int_to_c_int(i))) == i
    assert c_int_len(i) == len(int_to_c_int(i))
    assert len(int_to_c_int(i)) == 1

    for i in range(1213666705181745367548161 - 10, 1213666705181745367548161 + 10):
        assert c_int_to_int((int_to_c_int(i))) == i
        assert c_int_len(i) == len(int_to_c_int(i))

    for i in range(310698676526526814092329217 - 10, 310698676526526814092329217 + 10):
        assert c_int_to_int((int_to_c_int(i))) == i
        assert c_int_len(i) == len(int_to_c_int(i))

    for i in range(79538861190790864407636279553 - 10, 79538861190790864407636279553 + 10):
        assert c_int_to_int((int_to_c_int(i))) == i
        assert c_int_len(i) == len(int_to_c_int(i))

    for i in range(20361948464842461288354887565569 - 10, 20361948464842461288354887565569 + 10):
        assert c_int_to_int((int_to_c_int(i))) == i
        assert c_int_len(i) == len(int_to_c_int(i))

    for i in range(5212658806999670089818851216785665 - 10, 5212658806999670089818851216785665 + 10):
        assert c_int_to_int((int_to_c_int(i))) == i
        assert c_int_len(i) == len(int_to_c_int(i))

    for i in range(1334440654591915542993625911497130241 - 10, 1334440654591915542993625911497130241 + 10):
        assert c_int_to_int((int_to_c_int(i))) == i
        assert c_int_len(i) == len(int_to_c_int(i))

    for i in range(341616807575530379006368233343265341697 - 10, 341616807575530379006368233343265341697 + 10):
        assert c_int_to_int((int_to_c_int(i))) == i
        assert c_int_len(i) == len(int_to_c_int(i))
    for i in range(87453902739335777025630267735875927474433 - 10, 87453902739335777025630267735875927474433 + 10):
        assert c_int_to_int((int_to_c_int(i))) == i
        assert c_int_len(i) == len(int_to_c_int(i))

    for i in range(22388199101269958918561348540384237433454849 - 10, 22388199101269958918561348540384237433454849 + 10):
        assert c_int_to_int((int_to_c_int(i))) == i
        assert c_int_len(i) == len(int_to_c_int(i))

    for i in range(5731378969925109483151705226338364782964441345 - 10, 5731378969925109483151705226338364782964441345 + 10):
        assert c_int_to_int((int_to_c_int(i))) == i
        assert c_int_len(i) == len(int_to_c_int(i))

    for i in range(341616807575530379006368233343265341697 - 10, 341616807575530379006368233343265341697 + 10):
        assert c_int_to_int((int_to_c_int(i))) == i
        assert c_int_len(i) == len(int_to_c_int(i))

    number = 0
    old_number = 0
    for i in range(0, 1024, 8):
        number += 2 ** i
        for i in range(old_number, number, int(math.ceil(2 ** i / 20))):
            b = 1
            a = int_to_c_int(i, b)
            c = c_int_to_int(a, b)
            l = c_int_len(i)
            assert c == i
            assert l == len(a)
        old_number = number
