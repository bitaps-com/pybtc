from pybtc.functions.tools import bytes_from_hex
import pytest

from pybtc.functions.key import create_private_key
from pybtc.functions.key import wif_to_private_key
from pybtc.functions.key import private_key_to_wif
from pybtc.functions.key import is_wif_valid
from pybtc.functions.key import private_to_public_key
from pybtc.functions.key import is_public_key_valid



def test_create_private_key():
    wk = create_private_key()
    k = wif_to_private_key(wk)
    assert private_key_to_wif(k) == wk
    wk = create_private_key(hex=True)
    assert len(wk) == 64
    wk = create_private_key(hex=False, wif = False)
    assert len(wk) == 32

def test_private_key_to_wif():
    assert private_key_to_wif("ceda1ae4286015d45ec5147fe3f63e9377ccd6d4e98bcf0847df9937da1944a4") == \
           "L49obCXV7fGz2YRzLCSJgeZBYmGeBbKPT7xiehUeYX2S4URkPFZX";
    assert private_key_to_wif(bytes_from_hex("ceda1ae4286015d45ec5147fe3f63e9377ccd6d4e98bcf0847df9937da1944a4")) == \
           "L49obCXV7fGz2YRzLCSJgeZBYmGeBbKPT7xiehUeYX2S4URkPFZX";
    with pytest.raises(TypeError):
        private_key_to_wif("ceda1ae4286015d45ec5147fe3f63e9377ccd6d4e98bcf0847df9937da1944")
    assert private_key_to_wif("ceda1ae4286015d45ec5147fe3f63e9377ccd6d4e98bcf0847df9937da1944a4",
                              testnet=False,
                              compressed=True) == \
           "L49obCXV7fGz2YRzLCSJgeZBYmGeBbKPT7xiehUeYX2S4URkPFZX";
    assert private_key_to_wif("ceda1ae4286015d45ec5147fe3f63e9377ccd6d4e98bcf0847df9937da1944a4",
                              testnet=False,
                              compressed=False) == \
           "5KPPLXhtga99qqMceRo4Z6LXV3Kx6a9hRx3ez2U7EwP5KZfy2Wf";
    assert private_key_to_wif("ceda1ae4286015d45ec5147fe3f63e9377ccd6d4e98bcf0847df9937da1944a4",
                              testnet=True,
                              compressed=True) == \
           "cUWo47XLYiyFByuFicFS3y4FAza3r3R5XA7Bm7wA3dgSKDYox7h6";
    assert private_key_to_wif("ceda1ae4286015d45ec5147fe3f63e9377ccd6d4e98bcf0847df9937da1944a4",
                              testnet=True,
                              compressed=False) == \
           "93A1vGXSGoDHotruGmgyRgtV8hgfFjgtmtuc4epcag886W9d44L";

def test_wif_to_private_key():
    wk = create_private_key(testnet=True)
    k = wif_to_private_key(wk)
    assert private_key_to_wif(k, testnet=True) == wk

    wk = create_private_key(compressed=False)
    k = wif_to_private_key(wk)
    assert private_key_to_wif(k, compressed=False) == wk

    wk = create_private_key(compressed=False, testnet=False)
    k = wif_to_private_key(wk)
    assert private_key_to_wif(k, compressed=False, testnet=False) == wk

    wk = create_private_key(compressed=False, testnet=True)
    k = wif_to_private_key(wk)
    assert private_key_to_wif(k, compressed=False, testnet=True) == wk

    with pytest.raises(TypeError):
        wif_to_private_key("L49obCXV7fGz2YRzLCSJgeZBYmGeBbKPT7xiehUeYX2S4URkPFqX")

def test_is_wif_valid():
    assert is_wif_valid("L49obCXV7fGz2YRzLCSJgeZBYmGeBbKPT7xiehUeYX2S4URkPFZX") == True
    assert is_wif_valid("5KPPLXhtga99qqMceRo4Z6LXV3Kx6a9hRx3ez2U7EwP5KZfy2Wf") == True
    assert is_wif_valid("5KPPLXhtga99qqMcWRo4Z6LXV3Kx6a9hRx3ez2U7EwP5KZfy2Wf") == False
    assert is_wif_valid("93A1vGXSGoDHotruGmgyRgtV8hgfFjgtmtuc4epcag886W9d44L") == True
    assert is_wif_valid("cUWo47XLYiyFByuFicFS3y4FAza3r3R5XA7Bm7wA3dgSKDYox7h6") == True
    assert is_wif_valid("YiyByuFicFS3y4FAza3r3R5XA7Bm7wA3dgSKDYox7h6") == False
    assert is_wif_valid("5KPPLXhtga99qqMcWRo4Z6LXV3Kx6a9hRx3ez2U7EwP5K333Zfy2Wf") == False
    assert is_wif_valid("L49obCXV7fGz2YRzLCSJgeZqqBYmGeBbKPT7xiehUeYX2S4URkPFZX") == False
    assert is_wif_valid("cUWo47XLYtga99qqMcWRo4Z6LXV3Kx6a9hRx3ez2U7EwP5KZfy2Wf") == False
    assert is_wif_valid("cUWo47XLYiyFByuFi§FS3y4FAza3r3R5XA7Bm7wA3dgSKDY12oxQ7h9") == False
    assert is_wif_valid(22) == False


def test_private_to_public_key():
    priv = "ceda1ae4286015d45ec5147fe3f63e9377ccd6d4e98bcf0847df9937da1944a4"
    pu = "04b635dbdc16dbdf4bb9cf5b55e7d03e514fb04dcef34208155c7d3ec88e9045f4" \
         "c8cbe28702911260f2a1da099a338bed4ee98f66bb8dba8031a76ab537ff6663"
    pk = "03b635dbdc16dbdf4bb9cf5b55e7d03e514fb04dcef34208155c7d3ec88e9045f4"

    assert private_to_public_key(priv) == pk
    assert private_to_public_key(bytes_from_hex(priv)) == pk
    assert private_to_public_key(bytearray(bytes_from_hex(priv))) == pk
    assert private_to_public_key(priv) == pk
    assert private_to_public_key(priv, hex=True) == pk
    assert private_to_public_key(priv, hex=False).hex() == pk
    assert private_to_public_key(priv, compressed=False) == pu
    assert private_to_public_key("L49obCXV7fGz2YRzLCSJgeZBYmGeBbKPT7xiehUeYX2S4URkPFZX", pk)
    assert private_to_public_key("5KPPLXhtga99qqMceRo4Z6LXV3Kx6a9hRx3ez2U7EwP5KZfy2Wf", pu)
    assert private_to_public_key("93A1vGXSGoDHotruGmgyRgtV8hgfFjgtmtuc4epcag886W9d44L", pu)
    with pytest.raises(ValueError):
        assert private_to_public_key("ceda1ae4286015d45ec5147fe3f63e9377ccd6d4e98bcf0847df9937da1944a411", pu)
    with pytest.raises(ValueError):
        private_to_public_key(3738)
    with pytest.raises(Exception):
        private_to_public_key("L49obCXV7fGz2YRzLCSJgeZBYmGeBbKPT7xiehUeYX2S4URkPFZQ")


def test_is_public_key_valid():
    pu = "04b635dbdc16dbdf4bb9cf5b55e7d03e514fb04dcef34208155c7d3ec88e9045f4" + \
         "c8cbe28702911260f2a1da099a338bed4ee98f66bb8dba8031a76ab537ff6663"
    pk = "03b635dbdc16dbdf4bb9cf5b55e7d03e514fb04dcef34208155c7d3ec88e9045f4"

    assert is_public_key_valid(pu) == True
    assert is_public_key_valid(pk) == True
    assert is_public_key_valid(bytes_from_hex(pk)) == True
    assert is_public_key_valid(bytes_from_hex(pu)) == True
    pu = "63qdbdc16dbdf4bb9cf45b55e7d03e514fb04dcef34208155c7d3ec88e9045f4c8c" + \
         "be28702911260f2a1da099a338bed4ee98f66bb8dba8031a76ab537ff6663"
    pk = "02b635dbdc16dbdf455bb9cf5b55e7d03e514fb04dcef34208155c7d3ec88e9045f4"

    assert is_public_key_valid(pu) == False
    assert is_public_key_valid(pk) == False
    assert is_public_key_valid("8989") == False

    pu = "04b635dbdc16dbdf455bb9cf5b55e7d03e514fb04dcef34208155c7d3ec88e902245f4"
    assert is_public_key_valid(pu) == False
