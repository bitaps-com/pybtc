import unittest
import os, sys
parentPath = os.path.abspath("..")
if parentPath not in sys.path:
    sys.path.insert(0, parentPath)
from pybtc import bloom
import math



class BloomFunctionsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("\nTesting bloom filter functions:\n")

    def test_bloom(self):
        print(len(bloom.create_bloom_filter(6000, 0.01)))

        f = bloom.create_bloom_filter(10, 0.03)
        f = bloom.insert_to_bloom_filter(f, b"323434", 10)
        self.assertEqual(bloom.contains_in_bloom_filter(f, b"323434", 10), 1)
        self.assertEqual(bloom.contains_in_bloom_filter(f, b"324348577", 10), 0)
