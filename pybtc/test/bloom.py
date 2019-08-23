import unittest
import os, sys
parentPath = os.path.abspath("..")
if parentPath not in sys.path:
    sys.path.insert(0, parentPath)
from pybtc import *
import random



class BloomFunctionsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("\nTesting bloom filter functions:\n")

    def test_bloom(self):
        import lzma

        f, h = create_bloom_filter(15000, 0.0000001)
        print(">>", len(f), h)
        h = 3 # < 2000
        h = 4 # < 6000
        h = 3 # < 6000
        f = bytearray(512000 * 2)

        N = 4.792529188683719
        N = 4.092206312410748
        M = 3000
        f = bytearray(ceil(M*N))

        h = 23 # < 6000

        f, h = create_bloom_filter(M, 0.0000001)
        # f = bytearray(128000 )

        print(">", len(f), ceil(M*N))

        k = set()
        while len(k) < M:
            k.add(sha256(int_to_bytes(random.randint(1, 10000000)))[:21])

        for elem in k:

        exist = 0
        for elem in k:
            if not contains_in_bloom_filter(f, elem, h):
                exist += 1
        print("errors", exist, len(k), len(lzma.compress(f)))

        p = set()
        w = 0

        for i in range(2):
            p = set()
            while len(p)< 100000:
                t = sha256(int_to_bytes(random.randint(1, 10000000)))[:21]
                if t not in k:
                    p.add(t)

            exist = 0
            checked = 0
            for elem in p:
                if contains_in_bloom_filter(f, elem, h):
                    exist += 1
                checked += 1
            print(i,"exist", exist, checked, h)
            if exist: w+= 1
            # self.assertEqual(exist >= 6000, True)

