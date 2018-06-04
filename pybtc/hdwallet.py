import os
import hmac

from hashlib import sha256, sha512, pbkdf2_hmac
from binascii import hexlify, unhexlify
from .constants import *
from .tools import priv2pub


# BIP39
#
#
#

def create_passphrase(bits=256, language='english'):
    if bits in [128, 160, 192, 224, 256]:
        entropy = os.urandom(bits // 8)
        mnemonic = create_mnemonic(entropy, language)
        return ' '.join(mnemonic[::-1])
    else:
        raise ValueError('Strength should be one of the following [128, 160, 192, 224, 256], but it is not (%d).' % bits)


def create_mnemonic(entropy, language='english'):
    mnemonic = []
    wordlist = create_wordlist(language)
    entropy_int = int.from_bytes(entropy, byteorder="big")
    entropy_bit_len = len(entropy) * 8
    chk_sum_bit_len = entropy_bit_len // 32
    entropy_hash = sha256(entropy).hexdigest()
    fbyte_hash = unhexlify(entropy_hash)[0]
    entropy_int = add_checksum(entropy)
    while entropy_int:
        mnemonic.append(wordlist[entropy_int & 0b11111111111])
        entropy_int = entropy_int >> 11
    return mnemonic[::-1]


def create_wordlist(language, wordlist_dir=BIP0039_DIR):
    f = None
    path = os.path.join(wordlist_dir, '.'.join((language, 'txt')))
    assert os.path.exists(path)
    f = open(path)
    content = f.read().rstrip('\n')
    assert content
    f.close()
    return content.split('\n')


def add_checksum(data):
    mask = 0b10000000
    data_int = int.from_bytes(data, byteorder="big")
    data_bit_len = len(data) * 8 // 32
    data_hash = sha256(data).hexdigest()
    fbyte_hash = unhexlify(data_hash)[0]
    while data_bit_len:
        data_bit_len -= 1
        data_int = (data_int << 1) | 1 if fbyte_hash & mask else data_int << 1
        mask = mask >> 1
    return data_int


def mnemonic2bytes(passphrase, language):
    mnemonic = passphrase.split()
    if len(mnemonic) in [12, 15, 18, 21, 24]:
        wordlist = create_wordlist(language)
        codes = dict()
        for code, word in enumerate(wordlist):
            codes[word] = code
        word_count = len(mnemonic)
        entropy_int = None
        bit_size = word_count * 11
        chk_sum_bit_len = word_count * 11 % 32
        for word in mnemonic:
            entropy_int = (entropy_int << 11) | codes[word] if entropy_int else codes[word]
        chk_sum = entropy_int & (2 ** chk_sum_bit_len - 1)
        entropy_int = entropy_int >> chk_sum_bit_len
        entropy = entropy_int.to_bytes((bit_size - chk_sum_bit_len) // 8, byteorder="big")
        ent_hash = sha256(entropy).hexdigest()
        fb = unhexlify(ent_hash)[0]
        assert (fb >> (8 - chk_sum_bit_len)) & chk_sum
        return entropy
    else:
        raise ValueError('Number of words must be one of the following: [12, 15, 18, 21, 24], but it is not (%d).' % len(mnemonic))


def create_seed(passphrase, password=''):
    return pbkdf2_hmac('sha512', password.encode(), passphrase.encode(), 2048)



# BIP32
#
#
#

def create_master_key_hdwallet(seed):
    key = b'Bitcoin seed'
    intermediary = unhexlify(hmac.new(key, seed, sha512).hexdigest())
    master_key = intermediary[:32]
    chain_code = intermediary[32:]
    if validate_keys(master_key) and validate_keys(chain_code):
        return dict(version=PRIVATEWALLETVERSION,
                    key=master_key,
                    chain_code=chain_code,
                    depth=0,
                    child=0,
                    is_private=True)
    else:
        return None


def create_public_key_hdwallet(master_key):
    return priv2pub(master_key, True)


def validate_keys(key):
    if int.from_bytes(key, byteorder="big") > 0 and len(key) == 32:
        return True
    return False


    
