import unittest
import os, sys
parentPath = os.path.abspath("..")
if parentPath not in sys.path:
    sys.path.insert(0, parentPath)
from pybtc import *




class BloomFunctionsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("\nTesting bloom filter functions:\n")

    def test_bloom(self):
        f, h = create_bloom_filter(10, 0.03)
        insert_to_bloom_filter(f, b"323434", h)

        self.assertEqual(contains_in_bloom_filter(f, b"323434", h), 1)
        self.assertEqual(contains_in_bloom_filter(f, b"324348577", h), 0)
        k = [sha256(int_to_bytes(i), hex=0) for i in range(20000)]
        filter, h = create_bloom_filter(10000, 0.01)

        for elem in k[:6000]: insert_to_bloom_filter(filter, elem, h)

        exist = 0
        for elem in k:
            if contains_in_bloom_filter(filter, elem, h):
                exist += 1
        self.assertEqual(exist >= 6000, True)

