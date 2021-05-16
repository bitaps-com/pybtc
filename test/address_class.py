import unittest
import os
import sys


parentPath = os.path.abspath("..")
if parentPath not in sys.path:
    sys.path.insert(0, parentPath)

# from pybtc.transaction import *
from pybtc import OPCODE
from binascii import unhexlify
import pybtc

class AddressClassTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("\nTesting address class:\n")

    def test_is_WIF_valid(self):
        # mainnet
        self.assertEqual(pybtc.PrivateKey("7B56E2B7BD189F4491D43A1D209E6268046DF1741F61B6397349D7AA54978E76",
                                            compressed=True, testnet=False).wif,
                         'L1MU1jUjUwZ6Fd1L2HDZ8qH4oSWxct5boCQ4C87YvoSZbTW41hg4')
        self.assertEqual(pybtc.PrivateKey("7B56E2B7BD189F4491D43A1D209E6268046DF1741F61B6397349D7AA54978E76",
                                            compressed=False, testnet=False).wif,
                         '5Jkc7xqsrqA5pGQdwDHSQXRV3pUBLTXVjBjqJUSVz3pUmyuAFwP')
        # testnet
        self.assertEqual(pybtc.PrivateKey("7B56E2B7BD189F4491D43A1D209E6268046DF1741F61B6397349D7AA54978E76",
                                            compressed=True, testnet=True).wif,
                         'cRiTUeUav1FMR4UbQh2gW9n8RfpNHLBHsEYXJYa4Rv6ZrCdTPGqv')
        self.assertEqual(pybtc.PrivateKey("7B56E2B7BD189F4491D43A1D209E6268046DF1741F61B6397349D7AA54978E76",
                                            compressed=False, testnet=True).wif,
                         '92XEhhfRT4EDnKuvZZBMH7yShUptVd4h58bnP6o1KnZXYzkVa55')

        self.assertEqual(pybtc.PrivateKey("L1MU1jUjUwZ6Fd1L2HDZ8qH4oSWxct5boCQ4C87YvoSZbTW41hg4",
                                            compressed=False, testnet=True).wif,
                         'L1MU1jUjUwZ6Fd1L2HDZ8qH4oSWxct5boCQ4C87YvoSZbTW41hg4')

        p = pybtc.PrivateKey("L1MU1jUjUwZ6Fd1L2HDZ8qH4oSWxct5boCQ4C87YvoSZbTW41hg4")
        pub = pybtc.PublicKey(p)
        a = pybtc.Address(p)
        self.assertEqual(a.address, 'bc1qxsms4rt5axt9674du2az7vq3pvephu3k5jyky8')
        a = pybtc.Address(p, address_type = "P2PKH")
        self.assertEqual(a.address, '15m65JmFohJiioQbzMWhqFeCS3ZL1KVaNh')
        a = pybtc.Address(p, address_type = "PUBKEY")
        self.assertEqual(a.address, '15m65JmFohJiioQbzMWhqFeCS3ZL1KVaNh')
        a = pybtc.Address(p, address_type = "P2SH_P2WPKH")
        self.assertEqual(a.address, '37WJdFAoHDbxUQioDgtvPZuyJPyrrNQ7aL')
        self.assertEqual(a.redeem_script_hex, '001434370a8d74e9965d7aade2ba2f30110b321bf236')
        self.assertEqual(a.public_key.hex, '02a8fb85e98c99b79150df12fde488639d8445c57babef83d53c66c1e5c818eeb4')

        cpk = "02a8fb85e98c99b79150df12fde488639d8445c57babef83d53c66c1e5c818eeb4"
        ucpk = "04a8fb85e98c99b79150df12fde488639d8445c57babef83d53c66c1e5c818eeb" \
               "43bbd96a641808e5f34eb568e804fe679de82de419e2512736ea09013a82324a6"
        # public key uncompressed from HEX private
        self.assertEqual(pybtc.PublicKey("7b56e2b7bd189f4491d43a1d209e6268046df1741f61b6397349d7aa54978e76",
                                           compressed=False).hex, ucpk)
        # public key compressed from HEX private
        self.assertEqual(pybtc.PublicKey("7b56e2b7bd189f4491d43a1d209e6268046df1741f61b6397349d7aa54978e76",
                                           compressed=True).hex, cpk)
        # public key compressed from WIF private
        self.assertEqual(pybtc.PublicKey("L1MU1jUjUwZ6Fd1L2HDZ8qH4oSWxct5boCQ4C87YvoSZbTW41hg4",
                                           compressed=False).hex, cpk)
        # public key compressed from  PrivateKey instance (flags have no effect)
        p = pybtc.PrivateKey("L1MU1jUjUwZ6Fd1L2HDZ8qH4oSWxct5boCQ4C87YvoSZbTW41hg4")
        self.assertEqual(pybtc.PublicKey(p, compressed=False).hex, cpk)

        # public key compressed from  public
        self.assertEqual(pybtc.PublicKey(cpk, compressed=False).hex, cpk)

        # public key compressed from  public
        self.assertEqual(pybtc.PublicKey(unhexlify(cpk), compressed=False).hex, cpk)

        # compressed public key
        # private key hex string to compressed pub key
        p = pybtc.PrivateKey("7b56e2b7bd189f4491d43a1d209e6268046df1741f61b6397349d7aa54978e76", compressed=False)
        pub = pybtc.PublicKey(p)
        a = pybtc.Address(p, address_type="P2PKH")
        self.assertEqual(a.address, '17suVjHXyWF9KiGkpRRQW4ysiEqdDkRqo1')
        a = pybtc.Address(p, address_type="PUBKEY")
        self.assertEqual(a.address, '17suVjHXyWF9KiGkpRRQW4ysiEqdDkRqo1')

        # from pubkey
        p = pybtc.PublicKey('02a8fb85e98c99b79150df12fde488639d8445c57babef83d53c66c1e5c818eeb4')
        a = pybtc.Address(p)
        self.assertEqual(a.address, 'bc1qxsms4rt5axt9674du2az7vq3pvephu3k5jyky8')
        a = pybtc.Address(p, address_type="P2PKH")
        self.assertEqual(a.address, '15m65JmFohJiioQbzMWhqFeCS3ZL1KVaNh')
        a = pybtc.Address(p, address_type="PUBKEY")
        self.assertEqual(a.address, '15m65JmFohJiioQbzMWhqFeCS3ZL1KVaNh')
        a = pybtc.Address(p, address_type="P2SH_P2WPKH")
        self.assertEqual(a.address, '37WJdFAoHDbxUQioDgtvPZuyJPyrrNQ7aL')
        self.assertEqual(a.redeem_script_hex, '001434370a8d74e9965d7aade2ba2f30110b321bf236')
        self.assertEqual(a.public_key.hex, '02a8fb85e98c99b79150df12fde488639d8445c57babef83d53c66c1e5c818eeb4')

        # from uncompressed pubkey
        p = pybtc.PublicKey('04a8fb85e98c99b79150df12fde488639d8445c57babef83d53c66c1e5c818eeb43bbd96a641808'
                              'e5f34eb568e804fe679de82de419e2512736ea09013a82324a6')
        a = pybtc.Address(p, address_type="P2PKH")
        self.assertEqual(a.address, '17suVjHXyWF9KiGkpRRQW4ysiEqdDkRqo1')
        a = pybtc.Address(p, address_type="PUBKEY")
        self.assertEqual(a.address, '17suVjHXyWF9KiGkpRRQW4ysiEqdDkRqo1')

        redeem = "5221032bfc25cf7cccc278b26473e2967b8fd403b4b544b836e71abdfebb08d8c96d6921032bfc25cf7cccc278b2" \
                 "6473e2967b8fd403b4b544b836e71abdfebb08d8c96d6921032bfc25cf7cccc278b26473e2967b8fd403b4b544b8" \
                 "36e71abdfebb08d8c96d6953ae"
        a = pybtc.ScriptAddress(redeem, witness_version=None)
        self.assertEqual(a.address, '3KCqqS6eznp3ucVPxtNkiYcVg6kQKNX9sg')



