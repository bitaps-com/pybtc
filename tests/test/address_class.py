import unittest
import os, sys
parentPath = os.path.abspath("..")
if parentPath not in sys.path:
    sys.path.insert(0, parentPath)


from pybtc import address
from pybtc import OPCODE
from binascii import unhexlify


class AddressClassTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("\nTesting address class:\n")


    def test_is_WIF_valid(self):
        p = address.PrivateKey("L1MU1jUjUwZ6Fd1L2HDZ8qH4oSWxct5boCQ4C87YvoSZbTW41hg4")
        pub = address.PublicKey(p)
        a = address.Address(p)
        self.assertEqual(a.address, 'bc1qxsms4rt5axt9674du2az7vq3pvephu3k5jyky8')
        a = address.Address(p, address_type = "P2PKH")
        self.assertEqual(a.address, '15m65JmFohJiioQbzMWhqFeCS3ZL1KVaNh')
        a = address.Address(p, address_type = "PUBKEY")
        self.assertEqual(a.address, '15m65JmFohJiioQbzMWhqFeCS3ZL1KVaNh')
        a = address.Address(p, address_type = "P2SH_P2WPKH")
        self.assertEqual(a.address, '37WJdFAoHDbxUQioDgtvPZuyJPyrrNQ7aL')
        self.assertEqual(a.redeem_script, '001434370a8d74e9965d7aade2ba2f30110b321bf236')
        self.assertEqual(a.public_key.hex(), '02a8fb85e98c99b79150df12fde488639d8445c57babef83d53c66c1e5c818eeb4')

        # compressed public key
        p = address.PrivateKey("7b56e2b7bd189f4491d43a1d209e6268046df1741f61b6397349d7aa54978e76", compressed=False)
        pub = address.PublicKey(p)
        a = address.Address(p, address_type="P2PKH")
        self.assertEqual(a.address, '17suVjHXyWF9KiGkpRRQW4ysiEqdDkRqo1')
        a = address.Address(p, address_type="PUBKEY")
        self.assertEqual(a.address, '17suVjHXyWF9KiGkpRRQW4ysiEqdDkRqo1')

        # from pubkey
        p = address.PublicKey('02a8fb85e98c99b79150df12fde488639d8445c57babef83d53c66c1e5c818eeb4')
        a = address.Address(p)
        self.assertEqual(a.address, 'bc1qxsms4rt5axt9674du2az7vq3pvephu3k5jyky8')
        a = address.Address(p, address_type="P2PKH")
        self.assertEqual(a.address, '15m65JmFohJiioQbzMWhqFeCS3ZL1KVaNh')
        a = address.Address(p, address_type="PUBKEY")
        self.assertEqual(a.address, '15m65JmFohJiioQbzMWhqFeCS3ZL1KVaNh')
        a = address.Address(p, address_type="P2SH_P2WPKH")
        self.assertEqual(a.address, '37WJdFAoHDbxUQioDgtvPZuyJPyrrNQ7aL')
        self.assertEqual(a.redeem_script, '001434370a8d74e9965d7aade2ba2f30110b321bf236')
        self.assertEqual(a.public_key.hex(), '02a8fb85e98c99b79150df12fde488639d8445c57babef83d53c66c1e5c818eeb4')

        # from uncompressed pubkey
        p = address.PublicKey('04a8fb85e98c99b79150df12fde488639d8445c57babef83d53c66c1e5c818eeb43bbd96a641808e5f34eb568e804fe679de82de419e2512736ea09013a82324a6')
        a = address.Address(p, address_type="P2PKH")
        self.assertEqual(a.address, '17suVjHXyWF9KiGkpRRQW4ysiEqdDkRqo1')
        a = address.Address(p, address_type="PUBKEY")
        self.assertEqual(a.address, '17suVjHXyWF9KiGkpRRQW4ysiEqdDkRqo1')

        redeem = "5221032bfc25cf7cccc278b26473e2967b8fd403b4b544b836e71abdfebb08d8c96d6921032bfc25cf7cccc278b26473e2967b8fd403b4b544b836e71abdfebb08d8c96d6921032bfc25cf7cccc278b26473e2967b8fd403b4b544b836e71abdfebb08d8c96d6953ae"
        a = address.ScriptAddress(redeem)
        print(a.script_opcodes_asm)
        self.assertEqual(a.address, '3KCqqS6eznp3ucVPxtNkiYcVg6kQKNX9sg')