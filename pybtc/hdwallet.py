import os
import hmac

from secp256k1 import ffi
from struct import pack, unpack
from hashlib import pbkdf2_hmac
from binascii import hexlify, unhexlify
from .constants import *
from .tools import private_to_public_key, is_public_key_valid, encode_base58, decode_base58, private_key_to_wif
from .hash import hmac_sha512, hash160, double_sha256, sha256, double_sha256



# Hierarchical Deterministic Wallets (HD Wallets)
# BIP-0032/0044

# создание родительского приватного ключа
def create_xmaster_key(seed, testnet=False):
    if testnet:
        version = TESTNET_PRIVATE_WALLET_VERSION
    else:
        version = MAINNET_PRIVATE_WALLET_VERSION
    key = b'Bitcoin seed'
    intermediary = hmac_sha512(key, seed)
    mkey = intermediary[:32]
    chain_code = intermediary[32:]
    if is_xprivate_key_valid(mkey) and is_xprivate_key_valid(chain_code):
        return dict(version=version,
                    key=mkey,
                    depth=0,
                    child=0,
                    finger_print=b'\x00\x00\x00\x00',
                    chain_code=chain_code,
                    is_private=True)
    else:
        return None


def create_xpublic_key(key):
    if key['is_private']:
        if key['version'] == TESTNET_PRIVATE_WALLET_VERSION:
            version = TESTNET_PUBLIC_WALLET_VERSION
        else:
            version = MAINNET_PUBLIC_WALLET_VERSION
        pubkey = private_to_public_key(key['key'], hex=False)
        return dict(version=version,
                    key=pubkey,
                    depth=key['depth'],
                    child=key['child'],
                    finger_print=key['finger_print'],
                    chain_code=key['chain_code'],
                    is_private=False)
    return None


def derive_xkey(seed, *path_level, bip44=True, testnet=True, wif=True):
    if not bip44:
        if not len(path_level):
            raise TypeError("not specified path levels")
        mkey = create_xmaster_key(seed, testnet)
        xkey = create_child_privkey(mkey, path_level[0])
        for idx in path_level[1:]:
            xkey = create_child_privkey(xkey, idx)
        # сериализация и кодирование ключа
        if wif:
            result = encode_base58(serialize_xkey(xkey))
        else:
            result = serialize_xkey(xkey)
        return result
    else:
        if not is_validate_path_level(path_level, testnet):
            raise TypeError("path level does not match BIP-0044 - https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki")
        elif not len(path_level):
            if testnet:
                path_level = TESTNET_PATH_LEVEL_BIP0044
            else:
                path_level = PATH_LEVEL_BIP0044
        mkey = create_xmaster_key(seed, testnet)
        xkey = create_child_privkey(mkey, path_level[0])
        for idx in path_level[1:]:
            xkey = create_child_privkey(xkey, idx)
        # сериализация и кодирование ключа
        if wif:
            result = encode_base58(serialize_xkey(xkey))
        else:
            result = serialize_xkey(xkey)
        return result


def xprivate_to_xpublic_key(xprv, encode_b58=True):
    if is_xprivate_key_valid(xprv):
        xprivkey = deserialize_xkey(xprv)
        xpubkey = create_xpublic_key(xprivkey)
        if encode_b58:
            return encode_base58(serialize_xkey(xpubkey))
        return serialize_xkey(xpubkey)
    else:
        raise TypeError("Private key must be serialized according to BIP-0032 - " \
                        "https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#serialization-format")


# получение из расширенного приватного ключа обычный приватный ключ
def xkey_to_private_key(xkey, wif=True, hex=False):
    if is_xprivate_key_valid(xkey):
        xprivkey = deserialize_xkey(xkey)
        privkey = xprivkey['key']
        if xprivkey['version'] in TESTNET_PRIVATE_WALLET_VERSION:
            testnet = True
        else:
            testnet = False
        if wif:
            return private_key_to_wif(privkey, testnet=testnet)
        elif hex:
            return hexlify(privkey).decode()
        return privkey
    else:
        raise TypeError("Private key must be serialized according to BIP-0032 - " \
                        "https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#serialization-format")


# получение из расширенного приватного/публичного ключа обычный публичный ключ
def xkey_to_public_key(xkey, hex=False):
    if is_xprivate_key_valid(xkey):
        xkey = xprivate_to_xpublic_key(xkey)
    if is_xpublic_key_valid(xkey):
        xpubkey = deserialize_xkey(xkey)
        pubkey = xpubkey['key']
        if xpubkey['version'] in TESTNET_PUBLIC_WALLET_VERSION:
            testnet = True
        else:
            testnet = False
        if hex:
            return hexlify(pubkey).decode()
        return pubkey
    else:
        raise TypeError("Private or public key must be serialized according to BIP-0032 - " \
                        "https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#serialization-format")


# Создание дочернего приватного ключа
def create_child_privkey(key, child_idx):
    if key['is_private']:
        if child_idx < FIRST_HARDENED_CHILD:
            expanded_privkey = create_expanded_key(key, child_idx)
        else:
            expanded_privkey = create_expanded_hard_key(key, child_idx)
        if expanded_privkey:
            child_chain_code = expanded_privkey[32:]
            child_privkey = add_private_keys(expanded_privkey[:32], key['key'])
            if is_xprivate_key_valid(child_privkey):
                finger_print = hash160(private_to_public_key(key['key'], hex=False))[:4]
                return dict(version=key['version'],
                            key=child_privkey,
                            depth=key['depth'] + 1,
                            child=child_idx,
                            finger_print=finger_print,
                            chain_code=child_chain_code,
                            is_private=True)
    return None


# создание дочернего публичного ключа
def create_child_pubkey(key, child_idx):
    if not key['is_private']:
        expanded_pubkey = create_expanded_key(key, child_idx)
        if expanded_pubkey:
            child_chain_code = expanded_pubkey[32:]
            ext_value = private_to_public_key(expanded_pubkey[:32], hex=False)
            child_pubkey = add_public_keys(ext_value, key['key'])
            if is_xpublic_key_valid(child_pubkey):
                finger_print = hash160(key['key'])[:4]
                return dict(version=key['version'],
                            key=child_pubkey,
                            depth=key['depth'] + 1,
                            child=child_idx,
                            finger_print=finger_print,
                            chain_code=child_chain_code,
                            is_private=False)
    return None


# Создание расширенного приватного/публичного ключа
def create_expanded_key(key, child_idx):
    if isinstance(key, dict):
        if not key.get('is_private') and child_idx < FIRST_HARDENED_CHILD:
            seed = key['key'] + pack('I', child_idx)
            return hmac_sha512(key['chain_code'], seed)
        elif key.get('is_private') and child_idx < FIRST_HARDENED_CHILD:
            public_key = private_to_public_key(key['key'], hex=False)
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
    

def add_public_keys(ext_value, key):
    pubkey_ptr = ffi.new('secp256k1_pubkey *')
    if not secp256k1.secp256k1_ec_pubkey_parse(ECDSA_CONTEXT_VERIFY, pubkey_ptr, ext_value, len(ext_value)):
        raise TypeError("public key format error")
    if secp256k1.secp256k1_ec_pubkey_tweak_add(ECDSA_CONTEXT_ALL, pubkey_ptr, key):
        pubkey = ffi.new('char [%d]' % 33)
        outlen = ffi.new('size_t *', 33)
        if secp256k1.secp256k1_ec_pubkey_serialize(ECDSA_CONTEXT_VERIFY, pubkey, outlen, pubkey_ptr, EC_COMPRESSED):
            return bytes(ffi.buffer(pubkey, 33))
    return None


def is_xpublic_key_valid(key):
    """
    Check extended public key is valid according to BIP-0032.

    :param key: extended public key in BASE58 or bytes string format.
    :return: boolean.
    """
    if isinstance(key, str):
        if not key[:4] in ['xpub', 'tpub']:
            return False
        elif len(key) != 111:
            return False
    return True


def is_xprivate_key_valid(key):
    """
    Check the extended private key is valid according to BIP-0032.

    :param key: extended private key in BASE58 or bytes string format.
    :return: boolean.
    """
    if isinstance(key, bytes):
        key_int = int.from_bytes(key, byteorder="big")
        if key_int > 0 and key_int < MAX_INT_PRIVATE_KEY and len(key) == 32:
            return True
    elif isinstance(key, str):
        if len(key) == 111 and key[:4] in ['xprv', 'tprv']:
            return True
    return False


def is_validate_path_level(path_level, testnet):
    """
    Check path level is valid according to BIP-0044.
    
    :param list path_level: list of 5 levels in BIP32 path.
    :param testnet: if True, the check will be executed for TESTNET wallets.
    :return: boolean.
    """
    if not len(path_level):
        return True
    elif len(path_level) == 5:
        if path_level[0] != 0x8000002C:
            return False
        elif testnet and path_level[1] != 0x80000001:
            return False
        elif not testnet and path_level[1] != 0x80000000:
            return False
        elif path_level[2] < 0x80000000:
            return False
        return True
    return False


def serialize_xkey(key):
    """
    Serialization of extended keys.

    :param dict key: extended private or public key in Dict format.
    :return: bytes string.
    """
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


def deserialize_xkey(encode_key):
    """
    Deserialization of extended keys.

    :param str key: extended private or public key in base58 format.
    :return: bytes string.
    """
    raw_key = decode_base58(encode_key)
    decode_key = dict()
    if raw_key[:4] in [MAINNET_PUBLIC_WALLET_VERSION, MAINNET_PRIVATE_WALLET_VERSION]:
        decode_key['version'] = raw_key[:4]
        decode_key['depth'] = unpack('B', raw_key[4:5])[0]
        decode_key['finger_print'] = raw_key[5:9]
        decode_key['child'] = unpack('I', raw_key[9:13])[0]
        decode_key['chain_code'] = raw_key[13:45]
        if decode_key['version'] in [MAINNET_PRIVATE_WALLET_VERSION]:
            decode_key['is_private'] = True
            decode_key['key'] = raw_key[46:78]
        else:
            decode_key['is_private'] = False
            decode_key['key'] = raw_key[45:78]
        chk_sum = raw_key[78:]
        if chk_sum != double_sha256(raw_key[:-4])[:4]:
            raise TypeError("key checksum does not match")
    if decode_key:
        return decode_key
    return None



# Mnemonic code for generating deterministic keys
# BIP-0039

def create_passphrase(bits=256, language='english'):
    """
    Creating the passphrase.

    :param int bits: size of entropy is 128-256 bits, by default is 256.
    :param str language: uses wordlist language (chinese_simplified, chinese_traditional, english, french, italian, japanese, korean, spanish), by default is english.
    :return: string is passphrase.
    """
    if bits in [128, 160, 192, 224, 256]:
        entropy = os.urandom(bits // 8)
        mnemonic = create_mnemonic(entropy, language)
        return ' '.join(mnemonic)
    else:
        raise ValueError('Strength should be one of the following [128, 160, 192, 224, 256], but it is not (%d).' % bits)


def create_mnemonic(entropy, language='english'):
    """
    Generating the mnemonic.

    :param bytes entropy: random entropy bytes.
    :param str language: uses wordlist language (chinese_simplified, chinese_traditional, english, french, italian, japanese, korean, spanish), by default is english.
    :return: list of words.
    """
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


def create_wordlist(language='english', wordlist_dir=None):
    """
    Creating the wordlist.

    :param str language: uses wordlist language (chinese_simplified, chinese_traditional, english, french, italian, japanese, korean, spanish), by default is english.
    :param str wordlist_dir: path to a file containing a list of words.
    :return: list of words.
    """
    if not wordlist_dir:
        wordlist_dir = BIP0039_DIR
    f = None
    path = os.path.join(wordlist_dir, '.'.join((language, 'txt')))
    assert os.path.exists(path)
    f = open(path)
    content = f.read().rstrip('\n')
    assert content
    f.close()
    return content.split('\n')


def add_checksum_ent(data):
    """
    Adding a checksum of a entropy to a entropy.

    :param bytes data: random entropy bytes.
    :return: bytes string.
    """
    mask = 0b10000000
    data_int = int.from_bytes(data, byteorder="big")
    data_bit_len = len(data) * 8 // 32
    fbyte_hash = sha256(data)[0]
    while data_bit_len:
        data_bit_len -= 1
        data_int = (data_int << 1) | 1 if fbyte_hash & mask else data_int << 1
        mask = mask >> 1
    return data_int


def mnemonic_to_entropy(passphrase, language):
    """
    Converting passphrase to entropy.

    :param str passphrase: key passphrase.
    :param str language: uses wordlist language.
    :return: bytes string.
    """
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


def mnemonic_to_seed(passphrase, password):
    """
    Converting passphrase to seed.

    :param str passphrase: key passphrase.
    :param str password: password for key passphrase.
    :return: bytes string.
    """
    return pbkdf2_hmac('sha512', passphrase.encode(), (passphrase + password).encode(), 2048)

