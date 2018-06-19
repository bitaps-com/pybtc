import os
import random
import hashlib
import hmac

from binascii import hexlify, unhexlify
from pybtc.hdwallet import *
from pybtc.tools import encode_base58, decode_base58



def test_create_master_key_hdwallet(mnemonic_256):
    passphrase = ' '.join(mnemonic_256)
    seed = mnemonic_to_seed(passphrase, 'P@ssw0rd')
    assert seed is not None
    assert len(seed) == 64
    master_key = create_xmaster_key(seed)
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


def test_create_public_key_hdwallet(master_key_hdwallet_mnet):
    public_key = create_xpublic_key(master_key_hdwallet_mnet)
    assert public_key is not None
    assert len(public_key['key']) == 33


def test_validate_private_key(fail_key1, fail_key2, good_key):
    assert not validate_private_key(fail_key1)
    assert not validate_private_key(fail_key2)
    assert validate_private_key(good_key)


def test_create_expanded_key(master_key_hdwallet_mnet, public_key_hdwallet_mnet):
    result = create_expanded_key(b'asdasdasd', 0)
    assert result is None
    result = create_expanded_key(master_key_hdwallet_mnet, 0x80000000)
    assert result is None
    result = create_expanded_key(master_key_hdwallet_mnet, 0)
    assert result is not None
    assert len(result) == 64
    result = create_expanded_key(public_key_hdwallet_mnet, 0)
    assert result is not None
    assert len(result) == 64


def test_create_expanded_hard_key(master_key_hdwallet_mnet, public_key_hdwallet_mnet):
    result = create_expanded_hard_key(master_key_hdwallet_mnet, 0)
    assert result is None
    result = create_expanded_hard_key(master_key_hdwallet_mnet, 0x80000000)
    assert result is not None
    assert len(result) == 64


def test_create_child_privkey(master_key_hdwallet_mnet, public_key_hdwallet_mnet):
    result = create_child_privkey(public_key_hdwallet_mnet, 0)
    assert result is None
    result = create_child_privkey(master_key_hdwallet_mnet, 0)
    assert result is not None
    assert isinstance(result, dict)
    assert result.get('is_private')


def test_create_child_pubkey(master_key_hdwallet_mnet, public_key_hdwallet_mnet):
    result = create_child_pubkey(master_key_hdwallet_mnet, 0)
    assert result is None
    result = create_child_pubkey(public_key_hdwallet_mnet, 0)
    assert result is not None
    assert isinstance(result, dict)
    assert not result.get('is_private')


def test_serialize_key_hdwallet(master_key_hdwallet_mnet, public_key_hdwallet_tnet):
    serialize_mkey = serialize_xkey(master_key_hdwallet_mnet)
    assert serialize_mkey is not None
    assert isinstance(serialize_mkey, bytes)
    assert len(serialize_mkey[:-4]) == 78
    ser_encode = encode_base58(serialize_mkey)
    assert ser_encode[:4] in ['xprv', 'tprv']
    
    serialize_pkey = serialize_xkey(public_key_hdwallet_tnet)
    assert serialize_pkey is not None
    assert isinstance(serialize_pkey, bytes)
    assert len(serialize_pkey[:-4]) == 78
    ser_encode = encode_base58(serialize_pkey)
    assert ser_encode[:4] in ['xpub', 'tpub']


def test_deserialize_key(privkey_hdwallet_base58, pubkey_hdwallet_base58, bad_key_hdwallet_base58):
    #десериализация приватного ключа
    privkey = deserialize_xkey(privkey_hdwallet_base58)
    assert privkey is not None
    assert isinstance(privkey, dict)
    assert privkey['is_private']
    #десериализация публичного ключа
    pubkey = deserialize_xkey(pubkey_hdwallet_base58)
    assert pubkey is not None
    assert isinstance(pubkey, dict)
    assert not pubkey['is_private']
    #десериализация некорретного ключа
    pubkey = deserialize_xkey(bad_key_hdwallet_base58)
    assert pubkey is None


def test_derive_xkey(mnemonic_256):
    passphrase = ' '.join(mnemonic_256)
    seed = mnemonic_to_seed(passphrase, 'P@ssw0rd')
    params = [0x8000002C, 0x80000001, 0x80000000, 0, 0]
    result = derive_xkey(seed, *params, bip44=True, testnet=True, wif=True)
    assert result is not None
    assert isinstance(result, str)
    assert result[:4] in 'tprv'


def test_xprivate_to_xpublic_key(privkey_hdwallet_base58):
    xpubkey = xprivate_to_xpublic_key(privkey_hdwallet_base58)
    assert xpubkey is not None
    assert isinstance(xpubkey, str)
    assert len(xpubkey) == 111
    assert xpubkey[:4] in ['xpub', 'tpub']
    xpubkey = xprivate_to_xpublic_key(privkey_hdwallet_base58, False)
    assert xpubkey is not None
    assert isinstance(xpubkey, bytes)


def test_validate_path_level():
    params = [0x8000002C, 0x80000001, 0x80000000, 0, 0]
    testnet = True
    assert validate_path_level(params, testnet)
    testnet = False
    assert not validate_path_level(params, testnet)
    params = [0, 0x80000001, 0x80000000, 0, 0]
    testnet = True
    assert not validate_path_level(params, testnet)
    params = [0x8000002C, 0x80000001, 0, 0, 0]
    testnet = True
    assert not validate_path_level(params, testnet)
    params = [0x8000002C, 0x80000001, 0, 0]
    testnet = True
    assert not validate_path_level(params, testnet)
    params = []
    assert validate_path_level(params, testnet)

