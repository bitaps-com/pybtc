from pybtc.functions.tools import s2rh
from pybtc.functions.tools import bytes_from_hex
import pytest

from pybtc.functions.key import create_private_key
from pybtc.functions.key import wif_to_private_key
from pybtc.functions.key import private_key_to_wif
from pybtc.functions.key import is_wif_valid
from pybtc.functions.key import private_to_public_key



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
    pass