import os
import random
import hashlib
import hmac

from binascii import hexlify, unhexlify
from pybtc.hdwallet import *



def test_create_master_key(mnemonic_256):
    passphrase = ' '.join(mnemonic_256)
    seed = create_seed(passphrase, 'P@ssw0rd')
    assert seed is not None
    assert len(seed) == 64
    
    master_key = create_master_key_hdwallet(seed)
    assert master_key is not None
    assert type(master_key) is dict
    assert master_key['is_private']


def test_create_public_key(master_key_hdwallet):
    public_key = create_public_key_hdwallet(master_key_hdwallet['key'])
    assert public_key is not None


def test_validate_keys(fail_key1, fail_key2, good_key):
    assert not validate_keys(fail_key1)
    assert not validate_keys(fail_key2)
    assert validate_keys(good_key)
