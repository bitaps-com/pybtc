from pybtc.constants import *
import time
import hashlib
from pybtc.functions.hash import sha256
from pybtc.functions.shamir import split_secret, restore_secret
from pybtc.functions.tools import int_from_bytes, get_bytes
import random
import math

def generate_entropy(strength=256, hex=True):
    """
    Generate 128-256 bits entropy bytes string

    :param int strength: entropy bits strength, by default is 256 bit.
    :param boolean hex: return HEX encoded string result flag, by default True.
    :return: HEX encoded or bytes entropy string.
    """
    if strength not in [128, 160, 192, 224, 256]:
        raise ValueError('strength should be one of the following [128, 160, 192, 224, 256]')
    a = random.SystemRandom().randint(0, ECDSA_SEC256K1_ORDER)
    i = int((time.time() % 0.01 ) * 100000)
    h = a.to_bytes(32, byteorder="big")
    # more entropy from system timer and sha256 derivation
    while i:
        h = hashlib.sha256(h).digest()
        i -= 1
        if not i and int_from_bytes(h, byteorder="big") > ECDSA_SEC256K1_ORDER: # pragma: no cover
            i += 1
    return h[:int(strength/8)] if not hex else h[:int(strength/8)].hex()


def load_word_list(language='english', word_list_dir=None):
    """
    Load the word list from local file.

    :param str language: (optional) uses word list language (chinese_simplified, chinese_traditional, english, french,
                         italian, japanese, korean, spanish), by default is english.
    :param str word_list_dir: (optional) path to a directory containing a list of words,
                              by default None (use BIP39 standard list)
    :return: list of words.
    """
    if not word_list_dir: # pragma: no cover
        word_list_dir = BIP0039_DIR
    path = os.path.join(word_list_dir, '.'.join((language, 'txt')))
    if not os.path.exists(path):
        raise ValueError("word list not exist")
    with open(path) as f:
        word_list = f.read().rstrip('\n').split('\n')
    if len(word_list) != 2048: # pragma: no cover
        raise ValueError("word list invalid, should contain 2048 words")
    return word_list


def entropy_to_mnemonic(entropy, language='english', word_list_dir=None, word_list=None, data=None):
    """
    Convert entropy to mnemonic words string.

    :param str,bytes entropy: random entropy HEX encoded or bytes string.
    :param str language: (optional) uses word list language (chinese_simplified, chinese_traditional, english, french,
                         italian, japanese, korean, spanish), by default is english.
    :param str word_list_dir: (optional) path to a directory containing a list of words,
                              by default None (use BIP39 standard list)
    :param list word_list: (optional) already loaded word list, by default None    
    :return: mnemonic words string.
    """
    entropy = get_bytes(entropy)
    if len(entropy) not in [16, 20, 24, 28, 32]:
        raise ValueError('entropy length should be one of the following: [16, 20, 24, 28, 32]')
    if word_list is None:
        word_list = load_word_list(language, word_list_dir)
    elif not isinstance(word_list, list) or len(word_list) != 2048:
        raise TypeError("invalid word list type")

    i = int.from_bytes(entropy, byteorder="big")
    # append checksum
    b = math.ceil(len(entropy) * 8 / 32)
    if data is not None:
        if data > (2 ** b - 1):
            raise ValueError('embedded data bits too long')
        i = (i << b) | data
    else:
        i = (i << b) | (sha256(entropy)[0] >>  (8 - b))

    return " ".join([word_list[i.__rshift__(((d - 1) * 11)) & 2047]
                     for d in range(int((len(entropy) * 8 + 8) // 11), 0, -1)])


def mnemonic_to_entropy(mnemonic, language='english', word_list_dir=None,
                        word_list=None, hex=True):
    """
    Converting mnemonic words to entropy.
    
    :param str mnemonic: mnemonic words string (space separated)
    :param str language: (optional) uses word list language (chinese_simplified, chinese_traditional, english, french,
                         italian, japanese, korean, spanish), by default is english.
    :param str word_list_dir: (optional) path to a directory containing a list of words,
                              by default None (use BIP39 standard list)
    :param list word_list: (optional) already loaded word list, by default None    
    :param boolean hex: return HEX encoded string result flag, by default True.
    :return: bytes string.
    """
    if word_list is None:
        word_list = load_word_list(language, word_list_dir)
    elif not isinstance(word_list, list) or len(word_list) != 2048:
        raise TypeError("invalid word list type")

    mnemonic = mnemonic.split()
    word_count = len(mnemonic)
    if word_count not in [12, 15, 18, 21, 24]:
        raise ValueError('Number of words must be one of the following: [12, 15, 18, 21, 24]')

    codes = {w: c for c, w in enumerate(word_list)}
    entropy_int = 0
    bit_size = word_count * 11
    chk_sum_bit_len = word_count * 11 % 32
    for w in mnemonic:
        entropy_int = (entropy_int << 11) | codes[w]

    entropy_int = entropy_int >> chk_sum_bit_len
    entropy = entropy_int.to_bytes((bit_size - chk_sum_bit_len) // 8, byteorder="big")
    return entropy if not hex else entropy.hex()


def get_mnemonic_checksum_data(mnemonic):
    word_list = load_word_list()
    mnemonic = mnemonic.split()
    word_count = len(mnemonic)
    chk_sum_bit_len = word_count * 11 % 32
    last_word = mnemonic[-1]
    codes = {w: c for c, w in enumerate(word_list)}
    return codes[last_word] & (2 ** chk_sum_bit_len - 1)

def is_mnemonic_checksum_valid(mnemonic, language='english', word_list_dir=None, word_list=None):
    if word_list is None:
        word_list = load_word_list(language, word_list_dir)
    elif not isinstance(word_list, list) or len(word_list) != 2048:
        raise TypeError("invalid word list type")

    mnemonic = mnemonic.split()
    word_count = len(mnemonic)
    if word_count not in [12, 15, 18, 21, 24]:
        raise ValueError('Number of words must be one of the following: [12, 15, 18, 21, 24]')

    codes = {w: c for c, w in enumerate(word_list)}
    entropy_int = 0
    bit_size = word_count * 11
    chk_sum_bit_len = word_count * 11 % 32
    for w in mnemonic:
        entropy_int = (entropy_int << 11) | codes[w]
    chk_sum = entropy_int & (2 ** chk_sum_bit_len - 1)
    entropy_int = entropy_int >> chk_sum_bit_len
    entropy = entropy_int.to_bytes((bit_size - chk_sum_bit_len) // 8, byteorder="big")

    if (sha256(entropy)[0] >> (8 - chk_sum_bit_len)) != chk_sum:
        return False
    return True


def mnemonic_to_seed(mnemonic, passphrase="", hex=True):
    """
    Converting mnemonic words string to seed for uses in key derivation (BIP-0032).

    :param str mnemonic: mnemonic words string (space separated)
    :param str passphrase: (optional) passphrase to get ability use 2FA approach for 
                          creating seed, by default empty string.
    :param boolean hex: return HEX encoded string result flag, by default True.
    :return: HEX encoded or bytes string.
    """
    if not isinstance(mnemonic, str):
        raise TypeError("mnemonic should be string")
    if not isinstance(passphrase, str):
        raise TypeError("mnemonic should be string")

    seed = hashlib.pbkdf2_hmac('sha512', mnemonic.encode(), ("mnemonic"+passphrase).encode(), 2048)
    return seed if not hex else seed.hex()


def __combinations(a, n):
        results = []
        total = len(a) ** 2
        for m in range(n, total):
            r = []
            i = len(a) - 1
            while i:
                if (m & (1 << i)) != 0:
                    r.append(a[i])
                i -= 1

            if len(r) >= n:
                results.append(r)

        return results


def split_mnemonic(mnemonic, threshold, total, language='english', embedded_index = False,
                   word_list_dir=None, word_list=None):
    if not isinstance(mnemonic, str):
        raise TypeError("invalid mnemonic")
    entropy = mnemonic_to_entropy(mnemonic, language=language, hex=False,
                                  word_list_dir=word_list_dir, word_list=word_list)
    if embedded_index:
        bits = math.ceil(math.log2(total)) + 1
    else:
        bits = 8
    shares = split_secret(threshold, total, entropy, bits)

    a = [(i, shares[i]) for i in shares]
    combinations = __combinations(a, threshold)
    for c in combinations:
        d = dict()
        for q in c:
            d[q[0]] = q[1]
        s = restore_secret(d)
        if s != entropy: # pragma: no cover
            raise Exception("split secret failed")
    if embedded_index:
        result = []
        for share in shares:
            result.append(entropy_to_mnemonic(shares[share], language=language,
                                              word_list_dir=word_list_dir,
                                              data=share,
                                              word_list=word_list))
    else:
        result = dict()
        for share in shares:
            result[share] = entropy_to_mnemonic(shares[share], language=language,
                                                word_list_dir=word_list_dir, word_list=word_list)
    return result


def combine_mnemonic(shares, language='english', word_list_dir=None, word_list=None):
    embedded_index = isinstance(shares, list)
    s = dict()
    if embedded_index:
        for share in shares:
            e = mnemonic_to_entropy(share, language=language, hex=False, word_list_dir=word_list_dir,
                                           word_list=word_list)
            i = get_mnemonic_checksum_data(share)
            if i in s:
                raise ValueError("Non unique or invalid shares")
            s[i] = e

    else:
        for share in shares:
            s[share] = mnemonic_to_entropy(shares[share], language=language, hex=False, word_list_dir=word_list_dir,
                                           word_list=word_list)
    entropy = restore_secret(s)
    return entropy_to_mnemonic(entropy, language=language, word_list_dir=word_list_dir,
                               word_list=word_list)


def is_mnemonic_valid(mnemonic, word_list=None):
    if word_list is None:
        word_list = load_word_list()
    if isinstance(mnemonic, str):
        mnemonic = mnemonic.split()
        for w in mnemonic:
            if w not in word_list:
                return False
        return True
    return False


