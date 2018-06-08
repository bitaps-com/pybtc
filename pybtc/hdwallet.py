import os
import hmac

from struct import pack, unpack
from hashlib import pbkdf2_hmac
from binascii import hexlify, unhexlify
from .constants import *
from .tools import priv2pub
from .hash import hmac_sha512, hash160, double_sha256, sha256, double_sha256


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
    fbyte_hash = sha256(entropy)[0]
    entropy_int = add_checksum_ent(entropy)
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


def add_checksum_ent(data):
    mask = 0b10000000
    data_int = int.from_bytes(data, byteorder="big")
    data_bit_len = len(data) * 8 // 32
    fbyte_hash = sha256(data)[0]
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
        fb = sha256(entropy)[0]
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

# создание родительского приватного ключа
def create_master_key_hdwallet(seed):
    key = b'Bitcoin seed'
    intermediary = hmac_sha512(key, seed)
    master_key = intermediary[:32]
    chain_code = intermediary[32:]
    if validate_private_key(master_key) and validate_private_key(chain_code):
        return dict(version=MAINNET_PRIVATE_WALLET_VERSION,
                    key=master_key,
                    depth=0,
                    child=0,
                    finger_print=b'\x00\x00\x00\x00',
                    chain_code=chain_code,
                    is_private=True)
    else:
        return None


# создание дочернего приватного ключа
def create_child_key_hdwallet(key, child_idx):
    if not key.get('is_private') and child_idx >= FIRST_HARDENED_CHILD:
        return None
    public_key = priv2pub(key['key'], True)
    assert public_key is not None
    seed = public_key + bytes([key['depth'] + 1])
    intermediary = hmac_sha512(key['chain_code'], seed)
    chain_code = intermediary[32:]
    child_key = add_private_keys(intermediary[:32], key['key'])
    finger_print = hash160(child_key)[:4]
    if validate_private_key(child_key) and validate_private_key(chain_code):
        return dict(version=MAINNET_PRIVATE_WALLET_VERSION,
                    key=child_key,
                    depth=key['depth'] + 1,
                    child=0,
                    finger_print=finger_print,
                    chain_code=chain_code,
                    is_private=True)
    return None


# Создание расширенного приватного/публичного ключа
def create_expanded_key(key, child_idx):
    if isinstance(key, dict):
        if not key.get('is_private') and child_idx < FIRST_HARDENED_CHILD:
            seed = key['key'] + pack('I', child_idx)
            return hmac_sha512(key['chain_code'], seed)
        elif key.get('is_private') and child_idx < FIRST_HARDENED_CHILD:
            public_key = priv2pub(key['key'])
            seed = public_key + pack('I', child_idx)
            return hmac_sha512(key['chain_code'], seed)
    return None


# Создание усиленного расширенного приватного ключа
def create_expanded_hard_key(key, child_idx):
    if isinstance(key, dict):
        if key.get('is_private') and child_idx >= FIRST_HARDENED_CHILD:
            seed = bytes([0]) + key['key'] + pack('I', child_idx)
            return hmac_sha512(key['chain_code'], seed)
    return None


def add_private_keys(ext_value, key):
    ext_value_int = int.from_bytes(ext_value, byteorder="big")
    key_int = int.from_bytes(key, byteorder="big")
    ext_value_int = (ext_value_int + key_int) % MAX_INT_PRIVATE_KEY
    return ext_value_int.to_bytes((ext_value_int.bit_length() + 7) // 8, byteorder="big")
    

## Надо удалить в будущем как дублирование. И добавить в реализации ООП как метод
def create_public_key_hdwallet(master_key):
    return priv2pub(master_key, True)


def validate_private_key(key):
    key_int = int.from_bytes(key, byteorder="big")
    if key_int > 0 and key_int < MAX_INT_PRIVATE_KEY and len(key) == 32:
        return True
    return False


def validate_child_public_key(key):
    return False


def serialize_key_hdwallet(key):
    try:
        key_bytes = key['key']
        if key.get('is_private'):
            key_bytes = bytes(1) + key_bytes

        result = key['version']
        result += pack('B', key['depth'])
        result += key['finger_print']
        result += pack('I', key['child'])
        result += key['chain_code']
        result += key_bytes
        chk_sum = double_sha256(result)[:4]
        return result + chk_sum
    except:
        raise Exception('Serialization error')



