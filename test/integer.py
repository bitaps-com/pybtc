import unittest
import os, sys
parentPath = os.path.abspath("..")
if parentPath not in sys.path:
    sys.path.insert(0, parentPath)
from pybtc import tools
import math


def print_bytes(b):
    for i in range(len(b)):
        print(bin(b[i])[2:].rjust(8, '0'), end = ' ')
    print("\n", end="")

class IntegerFunctionsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("\nTesting compressed/variable int functions:\n")

    def test_compressed_integer(self):
        # print()
        for i in range(126, 130):
            # print(i, "[", len(tools.int_to_c_int(i)), "]", end=" : " )
            # print_bytes(tools.int_to_c_int(i))
            # print(bin(tools.c_int_to_int((tools.int_to_c_int(i)))))
            self.assertEqual(tools.c_int_to_int((tools.int_to_c_int(i))), i)
            self.assertEqual(tools.c_int_len(i), len(tools.int_to_c_int(i)))
        self.assertEqual(len(tools.int_to_c_int(i)), 2)
        for i in range(16382, 16386):
            # print(i, "[", len(tools.int_to_c_int(i)), "]", end=" : " )
            # print_bytes(tools.int_to_c_int(i))
            # print(bin(tools.c_int_to_int((tools.int_to_c_int(i)))))
            self.assertEqual(tools.c_int_to_int((tools.int_to_c_int(i))), i)
            self.assertEqual(tools.c_int_len(i), len(tools.int_to_c_int(i)))
        self.assertEqual(len(tools.int_to_c_int(i)), 3)
        for i in range(2097149, 2097154):
            # print(i, "[", len(tools.int_to_c_int(i)), "]", end=" : " )
            # print_bytes(tools.int_to_c_int(i))
            # print(bin(tools.c_int_to_int((tools.int_to_c_int(i)))))
            self.assertEqual(tools.c_int_to_int((tools.int_to_c_int(i))), i)
            self.assertEqual(tools.c_int_len(i), len(tools.int_to_c_int(i)))
        self.assertEqual(len(tools.int_to_c_int(i)), 4)
        for i in range(268435454, 268435458):
            # print(i, "[", len(tools.int_to_c_int(i)), "]", end=" : " )
            # print_bytes(tools.int_to_c_int(i))
            # print(bin(tools.c_int_to_int((tools.int_to_c_int(i)))))
            self.assertEqual(tools.c_int_to_int((tools.int_to_c_int(i))), i)
            self.assertEqual(tools.c_int_len(i), len(tools.int_to_c_int(i)))
        self.assertEqual(len(tools.int_to_c_int(i)), 5)
        for i in range(34359738366, 34359738370):
            # print(i, "[", len(tools.int_to_c_int(i)), "]", end=" : " )
            # print_bytes(tools.int_to_c_int(i))
            # print(bin(tools.c_int_to_int((tools.int_to_c_int(i)))))
            self.assertEqual(tools.c_int_to_int((tools.int_to_c_int(i))), i)
            self.assertEqual(tools.c_int_len(i), len(tools.int_to_c_int(i)))
        self.assertEqual(len(tools.int_to_c_int(i)), 6)
        for i in range(4398046511102, 4398046511106):
            # print(i, "[", len(tools.int_to_c_int(i)), "]", end=" : " )
            # print_bytes(tools.int_to_c_int(i))
            # print(bin(tools.c_int_to_int((tools.int_to_c_int(i)))))
            self.assertEqual(tools.c_int_to_int((tools.int_to_c_int(i))), i)
            self.assertEqual(tools.c_int_len(i), len(tools.int_to_c_int(i)))
        self.assertEqual(len(tools.int_to_c_int(i)), 7)
        for i in range(562949953421310, 562949953421314):
            # print(i, "[", len(tools.int_to_c_int(i)), "]", end=" : " )
            # print_bytes(tools.int_to_c_int(i))
            # print(bin(tools.c_int_to_int((tools.int_to_c_int(i)))))
            self.assertEqual(tools.c_int_to_int((tools.int_to_c_int(i))), i)
            self.assertEqual(tools.c_int_len(i), len(tools.int_to_c_int(i)))
        self.assertEqual(len(tools.int_to_c_int(i)), 8)
        for i in range(72057594037927934, 72057594037927938):
            self.assertEqual(tools.c_int_to_int((tools.int_to_c_int(i))), i)
            self.assertEqual(tools.c_int_len(i), len(tools.int_to_c_int(i)))
        self.assertEqual(len(tools.int_to_c_int(i)), 9)
        i = 16250249101024000000
        self.assertEqual(tools.c_int_to_int((tools.int_to_c_int(i))), i)
        self.assertEqual(tools.c_int_len(i), len(tools.int_to_c_int(i)))
        self.assertEqual(len(tools.int_to_c_int(i)), 10)
        i = 1333870604623599278750
        self.assertEqual(tools.c_int_to_int((tools.int_to_c_int(i))), i)

        i = 0
        self.assertEqual(tools.c_int_to_int((tools.int_to_c_int(i))), i)
        self.assertEqual(tools.c_int_len(i), len(tools.int_to_c_int(i)))
        self.assertEqual(len(tools.int_to_c_int(i)), 1)

        for i in range(1213666705181745367548161 - 10, 1213666705181745367548161 + 10):
            self.assertEqual(tools.c_int_to_int((tools.int_to_c_int(i))), i)
            self.assertEqual(tools.c_int_len(i), len(tools.int_to_c_int(i)))

        for i in range(310698676526526814092329217 - 10, 310698676526526814092329217 + 10):
            self.assertEqual(tools.c_int_to_int((tools.int_to_c_int(i))), i)
            self.assertEqual(tools.c_int_len(i), len(tools.int_to_c_int(i)))

        for i in range(79538861190790864407636279553 - 10, 79538861190790864407636279553 + 10):
            self.assertEqual(tools.c_int_to_int((tools.int_to_c_int(i))), i)
            self.assertEqual(tools.c_int_len(i), len(tools.int_to_c_int(i)))

        for i in range(20361948464842461288354887565569 - 10, 20361948464842461288354887565569 + 10):
            self.assertEqual(tools.c_int_to_int((tools.int_to_c_int(i))), i)
            self.assertEqual(tools.c_int_len(i), len(tools.int_to_c_int(i)))

        for i in range(5212658806999670089818851216785665 - 10, 5212658806999670089818851216785665 + 10):
            self.assertEqual(tools.c_int_to_int((tools.int_to_c_int(i))), i)
            self.assertEqual(tools.c_int_len(i), len(tools.int_to_c_int(i)))

        for i in range(1334440654591915542993625911497130241 - 10, 1334440654591915542993625911497130241 + 10):
            self.assertEqual(tools.c_int_to_int((tools.int_to_c_int(i))), i)
            self.assertEqual(tools.c_int_len(i), len(tools.int_to_c_int(i)))

        for i in range(341616807575530379006368233343265341697 - 10, 341616807575530379006368233343265341697 + 10):
            self.assertEqual(tools.c_int_to_int((tools.int_to_c_int(i))), i)
            self.assertEqual(tools.c_int_len(i), len(tools.int_to_c_int(i)))
        for i in range(87453902739335777025630267735875927474433 - 10, 87453902739335777025630267735875927474433 + 10):
            self.assertEqual(tools.c_int_to_int((tools.int_to_c_int(i))), i)
            self.assertEqual(tools.c_int_len(i), len(tools.int_to_c_int(i)))

        for i in range(22388199101269958918561348540384237433454849 - 10, 22388199101269958918561348540384237433454849 + 10):
            self.assertEqual(tools.c_int_to_int((tools.int_to_c_int(i))), i)
            self.assertEqual(tools.c_int_len(i), len(tools.int_to_c_int(i)))

        for i in range(5731378969925109483151705226338364782964441345 - 10, 5731378969925109483151705226338364782964441345 + 10):
            self.assertEqual(tools.c_int_to_int((tools.int_to_c_int(i))), i)
            self.assertEqual(tools.c_int_len(i), len(tools.int_to_c_int(i)))

        for i in range(341616807575530379006368233343265341697 - 10, 341616807575530379006368233343265341697 + 10):
            self.assertEqual(tools.c_int_to_int((tools.int_to_c_int(i))), i)
            self.assertEqual(tools.c_int_len(i), len(tools.int_to_c_int(i)))

        number = 0
        old_number = 0
        for i in range(0, 1024, 8):
            number += 2 ** i
            for i in range(old_number, number, int(math.ceil(2 ** i / 20))):
                b = 1
                a = tools.int_to_c_int(i, b)
                c = tools.c_int_to_int(a, b)
                l = tools.c_int_len(i)
                self.assertEqual(c, i)
                self.assertEqual(l, len(a))
            old_number = number

    def test_variable_integer(self):
        for i in range(0, 0xfd):
            self.assertEqual(tools.var_int_to_int((tools.int_to_var_int(i))), i)
            self.assertEqual(tools.var_int_len(i), len(tools.int_to_var_int(i)))
            self.assertEqual(tools.var_int_len(i), 1)
        for i in range(0xfd, 0xfff):
            self.assertEqual(tools.var_int_to_int((tools.int_to_var_int(i))), i)
            self.assertEqual(len(tools.int_to_var_int(i)), 3)
            self.assertEqual(tools.var_int_len(i), len(tools.int_to_var_int(i)))
        for i in range(0xfff0, 0xffff):
            self.assertEqual(tools.var_int_to_int((tools.int_to_var_int(i))), i)
            self.assertEqual(len(tools.int_to_var_int(i)), 3)
            self.assertEqual(tools.var_int_len(i), len(tools.int_to_var_int(i)))
        for i in range(0x10000, 0x10010):
            self.assertEqual(tools.var_int_to_int((tools.int_to_var_int(i))), i)
            self.assertEqual(len(tools.int_to_var_int(i)), 5)
            self.assertEqual(tools.var_int_len(i), len(tools.int_to_var_int(i)))
        for i in range(0xffffff00, 0xffffffff):
            self.assertEqual(tools.var_int_to_int((tools.int_to_var_int(i))), i)
            self.assertEqual(len(tools.int_to_var_int(i)), 5)
            self.assertEqual(tools.var_int_len(i), len(tools.int_to_var_int(i)))
        for i in range(0x100000000, 0x100001000):
            self.assertEqual(tools.var_int_to_int((tools.int_to_var_int(i))), i)
            self.assertEqual(len(tools.int_to_var_int(i)), 9)
            self.assertEqual(tools.var_int_len(i), len(tools.int_to_var_int(i)))



