import unittest
from pybtc import tools
from binascii import unhexlify


class AddressFunctionsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("\nTesting address functions:\n")

    def test_pub2segwit(self):
        print("pub2segwit")
        self.assertEqual(tools.pub2segwit(unhexlify("03db633162d49193d1178a5bbb90bde2f3c196ba0296f010b12a2320a7c6568582")),
                         "3PjV3gFppqmDEHjLvqDWv3Y4riLMQg7X1y")