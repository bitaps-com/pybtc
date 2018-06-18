import os
import random
import hashlib
import hmac
from binascii import hexlify, unhexlify
from pybtc.hdwallet import *



def test_recovery_from_passphrase_12(entropy_128, mnemonic_128):
    passphrase = ' '.join(mnemonic_128)
    entropy = mnemonic2bytes(passphrase, 'english')
    assert entropy == entropy_128


def test_recovery_from_passphrase_15(entropy_160, mnemonic_160):
    passphrase = ' '.join(mnemonic_160)
    entropy = mnemonic2bytes(passphrase, 'english')
    assert entropy == entropy_160


def test_recovery_from_passphrase_18(entropy_192, mnemonic_192):
    passphrase = ' '.join(mnemonic_192)
    entropy = mnemonic2bytes(passphrase, 'english')
    assert entropy == entropy_192


def test_recovery_from_passphrase_21(entropy_224, mnemonic_224):
    passphrase = ' '.join(mnemonic_224)
    entropy = mnemonic2bytes(passphrase, 'english')
    assert entropy == entropy_224


def test_recovery_from_passphrase_24(entropy_256, mnemonic_256):
    passphrase = ' '.join(mnemonic_256)
    entropy = mnemonic2bytes(passphrase, 'english')
    assert entropy == entropy_256


def test_create_mnemonic(entropy_128, entropy_160, entropy_192, entropy_224, entropy_256):
    mnemonic = create_mnemonic(entropy_128, 'english')
    assert len(mnemonic) == 12

    mnemonic = create_mnemonic(entropy_160, 'english')
    assert len(mnemonic) == 15

    mnemonic = create_mnemonic(entropy_192, 'english')
    assert len(mnemonic) == 18

    mnemonic = create_mnemonic(entropy_224, 'english')
    assert len(mnemonic) == 21
    
    mnemonic = create_mnemonic(entropy_256, 'english')
    assert len(mnemonic) == 24


def test_create_wordlist():
    wordlist_en = create_wordlist('english')
    wordlist_fr = create_wordlist('french')
    wordlist_it = create_wordlist('italian')
    wordlist_sp = create_wordlist('spanish')
    assert 'abandon' in wordlist_en
    assert 'abaisser' in wordlist_fr
    assert 'abaco' in wordlist_it
    assert 'ábaco' in wordlist_sp


def test_create_seed(mnemonic_256):
    passphrase = ' '.join(mnemonic_256)
    seed = create_seed(passphrase, 'P@ssw0rd')
    assert seed is not None
    assert len(seed) == 64


def test_create_passphrase():
    passphrase = create_passphrase(128, 'english')
    assert len(passphrase.split()) == 12
    
    passphrase = create_passphrase(160, 'english')
    assert len(passphrase.split()) == 15
    
    passphrase = create_passphrase(192, 'english')
    assert len(passphrase.split()) == 18
    
    passphrase = create_passphrase(224, 'english')
    assert len(passphrase.split()) == 21
    
    passphrase = create_passphrase(256, 'english')
    assert len(passphrase.split()) == 24


def test_add_checksum_ent(entropy_128, entropy_160, entropy_192, entropy_224, entropy_256):
    ent_add_chksum = add_checksum_ent(entropy_128)
    ent_hash = hashlib.sha256(entropy_128).hexdigest()
    fb = unhexlify(ent_hash)[0]
    assert (fb >> 4) & ent_add_chksum

    ent_add_chksum = add_checksum_ent(entropy_160)
    ent_hash = hashlib.sha256(entropy_160).hexdigest()
    fb = unhexlify(ent_hash)[0]
    assert (fb >> 3) & ent_add_chksum

    ent_add_chksum = add_checksum_ent(entropy_192)
    ent_hash = hashlib.sha256(entropy_192).hexdigest()
    fb = unhexlify(ent_hash)[0]
    assert (fb >> 2) & ent_add_chksum

    ent_add_chksum = add_checksum_ent(entropy_224)
    ent_hash = hashlib.sha256(entropy_224).hexdigest()
    fb = unhexlify(ent_hash)[0]
    assert (fb >> 1) & ent_add_chksum

    ent_add_chksum = add_checksum_ent(entropy_256)
    ent_hash = hashlib.sha256(entropy_256).hexdigest()
    fb = unhexlify(ent_hash)[0]
    assert fb & ent_add_chksum



