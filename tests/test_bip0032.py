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
    assert isinstance(master_key, dict)
    assert master_key.get('version') is not None
    assert master_key.get('key') is not None
    assert master_key.get('depth') is not None
    assert master_key.get('child') is not None
    assert master_key.get('finger_print') is not None
    assert master_key.get('chain_code') is not None
    assert master_key.get('is_private') is not None
    assert master_key['is_private']


def test_create_public_key(master_key_hdwallet):
    public_key = create_public_key_hdwallet(master_key_hdwallet['key'])
    assert public_key is not None
    assert len(public_key) == 33


def test_validate_private_key(fail_key1, fail_key2, good_key):
    assert not validate_private_key(fail_key1)
    assert not validate_private_key(fail_key2)
    assert validate_private_key(good_key)


def test_serialize_key(master_key_hdwallet):
    serialize_key = serialize_key_hdwallet(master_key_hdwallet)
    assert serialize_key is not None
    assert isinstance(serialize_key, bytes)
    assert len(serialize_key[:-4]) == 78


def test_create_expanded_key(master_key_hdwallet, public_key_hdwallet):
    result = create_expanded_key(b'asdasdasd', 0)
    assert result is None
    result = create_expanded_key(master_key_hdwallet, 0)
    assert result is not None
    assert len(result) == 64
    result = create_expanded_key(public_key_hdwallet, 0)
    assert result is not None
    assert len(result) == 64


def test_create_expanded_hard_key(master_key_hdwallet, public_key_hdwallet):
    result = create_expanded_hard_key(master_key_hdwallet, 0)
    assert result is None
    result = create_expanded_hard_key(master_key_hdwallet, 0x80000000)
    assert result is not None
    assert len(result) == 64


def test_create_child_pubkey(master_key_hdwallet, public_key_hdwallet):
    result = create_child_pubkey(master_key_hdwallet, 0)
    assert result is not None
    assert isinstance(result, dict)
    assert not result.get('is_private')
