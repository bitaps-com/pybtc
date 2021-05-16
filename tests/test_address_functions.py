import pytest
from pybtc.functions.tools import s2rh
from pybtc.functions.tools import bytes_from_hex
from pybtc.functions.script import script_to_hash
from pybtc.functions.key import private_to_public_key
from pybtc.functions.hash import hash160
from pybtc.opcodes import BYTE_OPCODE
from pybtc.functions.address import hash_to_address
from pybtc.functions.address import address_to_hash
from pybtc.functions.address import public_key_to_address
from pybtc.functions.address import address_type
from pybtc.functions.address import address_net_type
from pybtc.functions.address import address_to_script
from pybtc.functions.address import hash_to_script
from pybtc.functions.address import public_key_to_p2sh_p2wpkh_script
from pybtc.functions.address import is_address_valid
from pybtc.functions.address import get_witness_version

def test_public_key_to_address():
    pc = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    assert public_key_to_address(pc) == "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
    assert public_key_to_address(pc) == "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
    assert public_key_to_address(pc, testnet=True) == "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"
    pc = "03b635dbdc16dbdf4bb9cf5b55e7d03e514fb04dcef34208155c7d3ec88e9045f4"
    assert public_key_to_address(pc,
                                 witness_version=None,
                                 testnet=False) == "1Fs2Xqrk4P2XADaJeZWykaGXJ4HEb6RyT1"
    assert public_key_to_address(pc,
                                 witness_version=None,
                                 testnet=True) == "mvNyptwisQTmwL3vN8VMaVUrA3swVCX83c"

    p = "L32a8Mo1LgvjrVDbzcc3NkuUfkpoLsf2Y2oEWkV4t1KpQdFzuyff"
    pk = private_to_public_key(p)
    assert public_key_to_address(pk,
                                 witness_version=None,
                                 p2sh_p2wpkh=True) == "33am12q3Bncnn3BfvLYHczyv23Sq2Wbwjw"
    with pytest.raises(ValueError):
        public_key_to_address(pc + "33", p2sh_p2wpkh=True)
    with pytest.raises(ValueError):
        public_key_to_address(pc + "33", witness_version=0)


def test_hash_to_address():
    pc = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    h = hash160(pc)
    s = bytes([len(bytes_from_hex(pc))]) + bytes_from_hex(pc) + BYTE_OPCODE["OP_CHECKSIG"]
    assert hash_to_address(h) == "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
    assert hash_to_address(h, testnet=True) == "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"
    h = script_to_hash(s, witness=True, hex=hex)
    assert hash_to_address(h) == "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"
    assert hash_to_address(h, testnet=True) == "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7"

    pk = "03b635dbdc16dbdf4bb9cf5b55e7d03e514fb04dcef34208155c7d3ec88e9045f4"
    h = hash160(pk)
    assert hash_to_address(h, witness_version=None) == "1Fs2Xqrk4P2XADaJeZWykaGXJ4HEb6RyT1"
    assert hash_to_address(h, witness_version=None, testnet=True) == "mvNyptwisQTmwL3vN8VMaVUrA3swVCX83c"

    # p2wpkh inside p2sh
    p = "L32a8Mo1LgvjrVDbzcc3NkuUfkpoLsf2Y2oEWkV4t1KpQdFzuyff"
    pk = private_to_public_key(p)
    script = b'\x00\x14' + hash160(pk)
    script_hash = hash160(script)
    assert hash_to_address(script_hash,
                           script_hash=1,
                           witness_version=None) == "33am12q3Bncnn3BfvLYHczyv23Sq2Wbwjw"
    assert hash_to_address(script_hash,
                           script_hash=1,
                           witness_version=None,
                           testnet=1) == "2Mu8y4mm4oF88yppDbUAAEwyBEPezrx7CLh"

    with pytest.raises(ValueError):
        hash_to_address(29023)
    with pytest.raises(ValueError):
        hash_to_address(h + b"33", witness_version=None)
    with pytest.raises(ValueError):
        hash_to_address(h + b"33", witness_version=0)


def test_address_to_hash():
    h = "751e76e8199196d454941c45d1b3a323f1433bd6"
    assert address_to_hash("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", hex=True) == h
    assert address_to_hash("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4") == h
    assert address_to_hash("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx") == h
    assert address_to_hash("kb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx") == None
    h = "1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"
    assert address_to_hash("bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3") == h
    h = "a307d67484911deee457779b17505cedd20e1fe9"
    assert address_to_hash("1Fs2Xqrk4P2XADaJeZWykaGXJ4HEb6RyT1") == h
    assert address_to_hash("mvNyptwisQTmwL3vN8VMaVUrA3swVCX83c") == h
    h = "14c14c8d26acbea970757b78e6429ad05a6ac6bb"
    assert address_to_hash("33am12q3Bncnn3BfvLYHczyv23Sq2Wbwjw") == h
    assert address_to_hash("2Mu8y4mm4oF88yppDbUAAEwyBEPezrx7CLh") == h


def test_address_type():
    assert address_type("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4") == 'P2WPKH'
    assert address_type("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx") == 'P2WPKH'
    assert address_type("tb1qw508d6qejxtdg4y5r3zarvary0cdc5xw7kxpjzsx") == 'UNKNOWN'
    assert address_type("wb1qw508d6qejxtdg4y5r3zarvary0cdc5xw7kxpjzsx") == 'UNKNOWN'
    assert address_type("bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3") == 'P2WSH'
    assert address_type("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7") == 'P2WSH'
    assert address_type("1Fs2Xqrk4P2XADaJeZWykaGXJ4HEb6RyT1") == 'P2PKH'
    assert address_type("mvNyptwisQTmwL3vN8VMaVUrA3swVCX83c") == 'P2PKH'
    assert address_type("33am12q3Bncnn3BfvLYHczyv23Sq2Wbwjw") == 'P2SH'
    assert address_type("2Mu8y4mm4oF88yppDbUAAEwyBEPezrx7CLh") == 'P2SH'

def test_address_net_type():
    assert address_net_type("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4") == 'mainnet'
    assert address_net_type("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx") == 'testnet'
    assert address_net_type("bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3") == 'mainnet'
    assert address_net_type("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7") == 'testnet'
    assert address_net_type("1Fs2Xqrk4P2XADaJeZWykaGXJ4HEb6RyT1") == 'mainnet'
    assert address_net_type("mvNyptwisQTmwL3vN8VMaVUrA3swVCX83c") == 'testnet'
    assert address_net_type("2Mu8y4mm4oF88yppDbUAAEwyBEPezrx7CLh") == 'testnet'
    assert address_net_type("33am12q3Bncnn3BfvLYHczyv23Sq2Wbwjw") == 'mainnet'
    assert address_net_type("rMu8y4mm4oF88yppDbUAAEwyBEPezrx7CLh") is None


def test_address_to_script():
    assert address_to_script("17rPqUf4Hqu6Lvpgfsavt1CzRy2GL19GD3", hex=True) == \
           "76a9144b2832feeda5692c96c0594a6314136a998f515788ac"
    assert address_to_script("33RYUa9jT541UNPsKdV7V1DmwMiQHpVfD3", hex=True) == \
           "a914130319921ecbcfa33fec2a8503c4ae1c86e4419387"
    assert address_to_script("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", hex=True) == \
           "0014751e76e8199196d454941c45d1b3a323f1433bd6"
    assert address_to_script("17rPqUf4Hqu6Lvpgfsavt1CzRy2GL19GD3").hex() == \
           "76a9144b2832feeda5692c96c0594a6314136a998f515788ac"
    assert address_to_script("33RYUa9jT541UNPsKdV7V1DmwMiQHpVfD3").hex() == \
           "a914130319921ecbcfa33fec2a8503c4ae1c86e4419387"
    assert address_to_script("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").hex() == \
           "0014751e76e8199196d454941c45d1b3a323f1433bd6"
    with pytest.raises(ValueError):
        address_to_script("bd6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
    with pytest.raises(TypeError):
        address_to_script(74837)

def test_hash_to_script():
    h = "751e76e8199196d454941c45d1b3a323f1433bd6"
    assert hash_to_script(h, 0).hex() == "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac"
    assert hash_to_script(h, "P2PKH").hex() == "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac"
    assert hash_to_script(h, 1, hex=True) == "a914751e76e8199196d454941c45d1b3a323f1433bd687"
    assert hash_to_script(h, "P2SH", hex=True) == "a914751e76e8199196d454941c45d1b3a323f1433bd687"
    assert hash_to_script(h, 5, hex=True) == "0014751e76e8199196d454941c45d1b3a323f1433bd6"
    assert hash_to_script(h, "P2WPKH", hex=True) == "0014751e76e8199196d454941c45d1b3a323f1433bd6"
    assert hash_to_script(h, 6, hex=True) == "0014751e76e8199196d454941c45d1b3a323f1433bd6"
    assert hash_to_script(h, "P2WSH", hex=True) == "0014751e76e8199196d454941c45d1b3a323f1433bd6"
    with pytest.raises(ValueError):
        assert hash_to_script(h,9)
    with pytest.raises(ValueError):
        assert hash_to_script(h,"WWW")


def test_public_key_to_p2sh_p2wpkh_script():
    p = "0003b635dbdc16dbdf4bb9cf5b55e7d03e514fb04dcef34208155c7d3ec88e9045f4"
    with pytest.raises(ValueError):
        public_key_to_p2sh_p2wpkh_script(p)
    p = "03b635dbdc16dbdf4bb9cf5b55e7d03e514fb04dcef34208155c7d3ec88e9045f4"
    assert public_key_to_p2sh_p2wpkh_script(p).hex() == "0014a307d67484911deee457779b17505cedd20e1fe9"

def test_is_address_valid():
    assert is_address_valid("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4") == True
    assert is_address_valid("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", testnet=True) == True
    assert is_address_valid("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", testnet=False) == False
    assert is_address_valid("bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3") == True
    assert is_address_valid("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7", testnet=True) == True
    assert is_address_valid("1Fs2Xqrk4P2XADaJeZWykaGXJ4HEb6RyT1") == True
    assert is_address_valid("33am12q3Bncnn3BfvLYHczyv23Sq2Wbwjw") == True
    assert is_address_valid("mvNyptwisQTmwL3vN8VMaVUrA3swVCX83c", testnet=True) == True
    assert is_address_valid(54, testnet=True) == False
    assert is_address_valid("33am12q3Bncnn3BfvLYHczyv23Sq2WWbwjw") == False
    assert is_address_valid("2Mu8y4mm4oF88yppDbUAAEwyBEPezrx7CLh", testnet=True) == True
    assert is_address_valid("2Mu8y4mm4oF89yppDbUAAEwyBEPezrx7CLh") == False
    assert is_address_valid("2Mu8y4mm4oF89yppDbUAAEwyBEPezrx7CCLh") == False
    assert is_address_valid("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", testnet=True) == False
    assert is_address_valid("tb1qw508d6qejxtdg4W5r3zarvary0c5xw7kxpjzsx", testnet=True) == False
    assert is_address_valid("bc1qrp33g0q5c5txsp8arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3") == False
    assert is_address_valid("TB1QRP23G0Q5C5TXSP9ARYSRX4K6ZDKFS4NCE4XJ0GDCCCEFVPYSXF3Q0SL5K7", testnet=True) == False
    assert is_address_valid("TB1QRP23G0Q5C5TXSP9ARYSRX4K6ZDKFS4NCE4XJ0GDCCCEFVPYSXF3Q0sL5K7", testnet=True) == False
    assert is_address_valid("tb1", testnet=True) == False
    assert is_address_valid("tbqqrp23g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7", testnet=True) == False
    assert is_address_valid("1Fs2Xqrk4P2XADaJeZWykaGXJ2HEb6RyT1") == False
    assert is_address_valid("mvNyptwisQTkwL3vN8VMaVUrA3swVCX83c", testnet=True) == False
    assert is_address_valid("33am12q3Bncmn3BfvLYHczyv23Sq2Wbwjw", testnet=True) == False
    assert is_address_valid("2Mu8y4mm4oF78yppDbUAAEwyBEPezrx7CLh", testnet=True) == False
    assert is_address_valid("33am12q3Bncmn3BfvLYHczyv23Sq2Wbwjw") == False
    assert is_address_valid("73am12q3Bncmn3BfvLYHczyv23Sq2Wbwjw") == False

def test_get_witness_version():
    assert get_witness_version("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4") == 0

