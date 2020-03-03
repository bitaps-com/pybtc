import unittest
import os, sys
parentPath = os.path.abspath("..")
if parentPath not in sys.path:
    sys.path.insert(0, parentPath)
from pybtc import shamir
import random

from pybtc import *

class IntegerFunctionsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("\nTesting shamir secret sharing functions:\n")


    def test_gf256_math(self):
        for i in range(1,256):
            self.assertEqual(1,shamir._gf256_mul(i, shamir._gf256_inverse(i)))
        for i in range(1,256):
            for j in range(1, 256):
                a = shamir._gf256_div(i, j)
                b = shamir._gf256_mul(a, j)
                self.assertEqual(i, b)

                a = shamir._gf256_add(i, j)
                b = shamir._gf256_sub(a, j)
                self.assertEqual(i, b)
        k = 2
        for i in range(2, 256):
            a = shamir._gf256_pow(k, i)
            b = k
            for j in range(i-1):
                b = shamir._gf256_mul(b, k)
            self.assertEqual(b, a)

        print("GF256 field math OK")

    def test_secrets(self):
        secret = b"wtw5heywrhsrhrtht"
        for i in range(1000):
            shares = shamir.split_secret(5, 5, secret)
            s = shamir.restore_secret(shares)
            self.assertEqual(s, secret)

        for i in range(2,30):
            shares = shamir.split_secret(i, i, secret)
            s = shamir.restore_secret(shares)
            self.assertEqual(s, secret)

        for i in range(2, 30):
            k = random.randint(i, i + 10)
            shares = shamir.split_secret(i, k, secret)
            b = dict()
            while len(b) < i:
                q= random.randint(1, k)
                b[q] = shares[q]
            s = shamir.restore_secret(b)
            self.assertEqual(s, secret)
        print("Shamir secret sharing OK")

    def test_mnemonic_secrets(self):
        m = entropy_to_mnemonic(generate_entropy())
        k = split_mnemonic(m, 3, 5)
        self.assertEqual(m, combine_mnemonic(k))

        for i in range(2, 30):
            m = entropy_to_mnemonic(generate_entropy())
            k = random.randint(i, i + 10)
            shares = split_mnemonic(m, i, k)
            b = dict()
            while len(b) < i:
                q = random.randint(1, k)
                b[q] = shares[q]
            self.assertEqual(m, combine_mnemonic(b))
        print("Mnenmonic + Shamir secret sharing OK")




