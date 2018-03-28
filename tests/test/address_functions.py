import unittest
from pybtc import tools
from pybtc import OPCODE
from binascii import unhexlify


class AddressFunctionsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("\nTesting address functions:\n")

    def test_priv2WIF(self):
        p = "ceda1ae4286015d45ec5147fe3f63e9377ccd6d4e98bcf0847df9937da1944a4"
        pcm = "L49obCXV7fGz2YRzLCSJgeZBYmGeBbKPT7xiehUeYX2S4URkPFZX"
        pum = "5KPPLXhtga99qqMceRo4Z6LXV3Kx6a9hRx3ez2U7EwP5KZfy2Wf"
        put = "93A1vGXSGoDHotruGmgyRgtV8hgfFjgtmtuc4epcag886W9d44L"
        pct = "cUWo47XLYiyFByuFicFS3y4FAza3r3R5XA7Bm7wA3dgSKDYox7h6"
        self.assertEqual(tools.priv2WIF(p, compressed=1, testnet=0),pcm)
        self.assertEqual(tools.priv2WIF(p, compressed=0, testnet=0),pum)
        self.assertEqual(tools.priv2WIF(p, compressed=1, testnet=1),pct)
        self.assertEqual(tools.priv2WIF(p, compressed=0, testnet=1),put)

    def test_is_WIF_valid(self):
        self.assertEqual(tools.is_WIF_valid("L49obCXV7fGz2YRzLCSJgeZBYmGeBbKPT7xiehUeYX2S4URkPFZX"),1)
        self.assertEqual(tools.is_WIF_valid("5KPPLXhtga99qqMceRo4Z6LXV3Kx6a9hRx3ez2U7EwP5KZfy2Wf"),1)
        self.assertEqual(tools.is_WIF_valid("5KPPLXhtga99qqMcWRo4Z6LXV3Kx6a9hRx3ez2U7EwP5KZfy2Wf"),0)
        self.assertEqual(tools.is_WIF_valid("93A1vGXSGoDHotruGmgyRgtV8hgfFjgtmtuc4epcag886W9d44L"),1)
        self.assertEqual(tools.is_WIF_valid("cUWo47XLYiyFByuFicFS3y4FAza3r3R5XA7Bm7wA3dgSKDYox7h6"),1)
        self.assertEqual(tools.is_WIF_valid("cUWo47XLYiyByuFicFS3y4FAza3r3R5XA7Bm7wA3dgSKDYox7h6"),0)

    def test_WIF2priv(self):
        p = "ceda1ae4286015d45ec5147fe3f63e9377ccd6d4e98bcf0847df9937da1944a4"
        self.assertEqual(tools.WIF2priv("L49obCXV7fGz2YRzLCSJgeZBYmGeBbKPT7xiehUeYX2S4URkPFZX",
                                        hex=1),p)
        self.assertEqual(tools.WIF2priv("L49obCXV7fGz2YRzLCSJgeZBYmGeBbKPT7xiehUeYX2S4URkPFZX",
                                        hex=0),unhexlify(p))
        self.assertEqual(tools.WIF2priv("5KPPLXhtga99qqMceRo4Z6LXV3Kx6a9hRx3ez2U7EwP5KZfy2Wf",
                                        hex=1),p)
        self.assertEqual(tools.WIF2priv("93A1vGXSGoDHotruGmgyRgtV8hgfFjgtmtuc4epcag886W9d44L",
                                        hex=1),p)
        self.assertEqual(tools.WIF2priv("cUWo47XLYiyFByuFicFS3y4FAza3r3R5XA7Bm7wA3dgSKDYox7h6",
                                        hex=1),p)

    def test_priv2pub(self):
        p = "ceda1ae4286015d45ec5147fe3f63e9377ccd6d4e98bcf0847df9937da1944a4"
        pu = "04b635dbdc16dbdf4bb9cf5b55e7d03e514fb04dcef34208155c7d3ec88e9045f4c8cbe28702911260f2a1da099a338bed4ee98f66bb8dba8031a76ab537ff6663"
        pk = "03b635dbdc16dbdf4bb9cf5b55e7d03e514fb04dcef34208155c7d3ec88e9045f4"
        self.assertEqual(tools.priv2pub(p, hex=1),pk)
        self.assertEqual(tools.priv2pub(p, hex=0),unhexlify(pk))
        self.assertEqual(tools.priv2pub(p, compressed=0, hex=1),pu)
        self.assertEqual(tools.priv2pub("L49obCXV7fGz2YRzLCSJgeZBYmGeBbKPT7xiehUeYX2S4URkPFZX", hex=1),pk)
        self.assertEqual(tools.priv2pub("5KPPLXhtga99qqMceRo4Z6LXV3Kx6a9hRx3ez2U7EwP5KZfy2Wf", hex=1),pu)
        self.assertEqual(tools.priv2pub("93A1vGXSGoDHotruGmgyRgtV8hgfFjgtmtuc4epcag886W9d44L", hex=1),pu)
        self.assertEqual(tools.priv2pub("cUWo47XLYiyFByuFicFS3y4FAza3r3R5XA7Bm7wA3dgSKDYox7h6", hex=1),pk)

    def test_hash2address(self):
        pc = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        h = tools.hash160(pc)
        s =  bytes([len(unhexlify(pc))])+unhexlify(pc) + OPCODE["OP_CHECKSIG"]
        self.assertEqual(tools.hash2address(h), "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
        self.assertEqual(tools.hash2address(h, testnet=1), "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx")
        h = tools.script2hash(s, 1, 1)
        self.assertEqual(tools.hash2address(h), "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3")
        self.assertEqual(tools.hash2address(h, testnet=1), "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7")
        pk = "03b635dbdc16dbdf4bb9cf5b55e7d03e514fb04dcef34208155c7d3ec88e9045f4"
        h = tools.hash160(pk)
        self.assertEqual(tools.hash2address(h, witness_version=None), "1Fs2Xqrk4P2XADaJeZWykaGXJ4HEb6RyT1")
        self.assertEqual(tools.hash2address(h, witness_version=None, testnet=1), "mvNyptwisQTmwL3vN8VMaVUrA3swVCX83c")
        # p2wpkh inside p2sh
        p = "L32a8Mo1LgvjrVDbzcc3NkuUfkpoLsf2Y2oEWkV4t1KpQdFzuyff"
        pk = tools.priv2pub(p)
        script = b'\x00\x14' + tools.hash160(pk)
        script_hash = tools.hash160(script)
        self.assertEqual(tools.hash2address(script_hash, script_hash=1, witness_version=None), "33am12q3Bncnn3BfvLYHczyv23Sq2Wbwjw")
        self.assertEqual(tools.hash2address(script_hash, script_hash=1, witness_version=None, testnet=1), "2Mu8y4mm4oF88yppDbUAAEwyBEPezrx7CLh")

    def test_address2hash(self):
        h = "751e76e8199196d454941c45d1b3a323f1433bd6"
        self.assertEqual(tools.address2hash("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", 1), h)
        self.assertEqual(tools.address2hash("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", 1), h)
        h  = "1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"
        self.assertEqual(tools.address2hash("bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3", 1), h)
        h = "a307d67484911deee457779b17505cedd20e1fe9"
        self.assertEqual(tools.address2hash("1Fs2Xqrk4P2XADaJeZWykaGXJ4HEb6RyT1", 1), h)
        self.assertEqual(tools.address2hash("mvNyptwisQTmwL3vN8VMaVUrA3swVCX83c", 1), h)
        h = "14c14c8d26acbea970757b78e6429ad05a6ac6bb"
        self.assertEqual(tools.address2hash("33am12q3Bncnn3BfvLYHczyv23Sq2Wbwjw", 1), h)
        self.assertEqual(tools.address2hash("2Mu8y4mm4oF88yppDbUAAEwyBEPezrx7CLh", 1), h)

    def test_address_type(self):
        self.assertEqual(tools.address_type("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"), 'P2WPKH')
        self.assertEqual(tools.address_type("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"), 'P2WPKH')
        self.assertEqual(tools.address_type("bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"), 'P2WSH')
        self.assertEqual(tools.address_type("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7"), 'P2WSH')
        self.assertEqual(tools.address_type("1Fs2Xqrk4P2XADaJeZWykaGXJ4HEb6RyT1"), 'P2PKH')
        self.assertEqual(tools.address_type("mvNyptwisQTmwL3vN8VMaVUrA3swVCX83c"), 'P2PKH')
        self.assertEqual(tools.address_type("33am12q3Bncnn3BfvLYHczyv23Sq2Wbwjw"), 'P2SH')
        self.assertEqual(tools.address_type("2Mu8y4mm4oF88yppDbUAAEwyBEPezrx7CLh"), 'P2SH')

    def test_pub2address(self):
        pc = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        self.assertEqual(tools.pub2address(pc), "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
        self.assertEqual(tools.pub2address(pc, testnet=1), "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx")
        pc = "03b635dbdc16dbdf4bb9cf5b55e7d03e514fb04dcef34208155c7d3ec88e9045f4"
        self.assertEqual(tools.pub2address(pc, witness_version=None, testnet=0), "1Fs2Xqrk4P2XADaJeZWykaGXJ4HEb6RyT1")
        self.assertEqual(tools.pub2address(pc, witness_version=None, testnet=1), "mvNyptwisQTmwL3vN8VMaVUrA3swVCX83c")
        p = "L32a8Mo1LgvjrVDbzcc3NkuUfkpoLsf2Y2oEWkV4t1KpQdFzuyff"
        pk = tools.priv2pub(p)
        self.assertEqual(tools.pub2address(pk, p2sh_p2wpkh=1,witness_version=None), "33am12q3Bncnn3BfvLYHczyv23Sq2Wbwjw")

    def test_is_address_valid(self):
        self.assertEqual(tools.is_address_valid("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"), 1)
        self.assertEqual(tools.is_address_valid("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", 1), 1)
        self.assertEqual(tools.is_address_valid("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"), 0)
        self.assertEqual(tools.is_address_valid("bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"), 1)
        self.assertEqual(tools.is_address_valid("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7", 1), 1)
        self.assertEqual(tools.is_address_valid("1Fs2Xqrk4P2XADaJeZWykaGXJ4HEb6RyT1"), 1)
        self.assertEqual(tools.is_address_valid("mvNyptwisQTmwL3vN8VMaVUrA3swVCX83c", 1), 1)
        self.assertEqual(tools.is_address_valid("33am12q3Bncnn3BfvLYHczyv23Sq2Wbwjw"), 1)
        self.assertEqual(tools.is_address_valid("2Mu8y4mm4oF88yppDbUAAEwyBEPezrx7CLh",1), 1)
        self.assertEqual(tools.is_address_valid("2Mu8y4mm4oF89yppDbUAAEwyBEPezrx7CLh",1), 0)
        self.assertEqual(tools.is_address_valid("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", 1), 0)
        self.assertEqual(tools.is_address_valid("tb1qw508d6qejxtdg4W5r3zarvary0c5xw7kxpjzsx",1), 0)
        self.assertEqual(tools.is_address_valid("bc1qrp33g0q5c5txsp8arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"), 0)
        self.assertEqual(tools.is_address_valid("tb1qrp23g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",1), 0)
        self.assertEqual(tools.is_address_valid("1Fs2Xqrk4P2XADaJeZWykaGXJ2HEb6RyT1"), 0)
        self.assertEqual(tools.is_address_valid("mvNyptwisQTkwL3vN8VMaVUrA3swVCX83c", 1), 0)
        self.assertEqual(tools.is_address_valid("33am12q3Bncmn3BfvLYHczyv23Sq2Wbwjw"), 0)
        self.assertEqual(tools.is_address_valid("2Mu8y4mm4oF78yppDbUAAEwyBEPezrx7CLh", 1), 0)
