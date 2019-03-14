from pybtc.constants import *
import time
import hashlib
from pybtc.functions.hash import sha256
from pybtc.functions.tools import int_from_bytes

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
        if not i and int_from_bytes(h, byteorder="big") > ECDSA_SEC256K1_ORDER:
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
    if not word_list_dir:
        word_list_dir = BIP0039_DIR
    path = os.path.join(word_list_dir, '.'.join((language, 'txt')))
    if not os.path.exists(path):
        raise ValueError("word list not exist")
    with open(path) as f:
        word_list = f.read().rstrip('\n').split('\n')
    if len(word_list) != 2048:
        raise ValueError("word list invalid, should contain 2048 words")
    return word_list


def entropy_to_mnemonic(entropy, language='english', word_list_dir=None, word_list=None):
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
    if isinstance(entropy, str):
        entropy = bytes.fromhex(entropy)
    if not isinstance(entropy, bytes):
        raise TypeError("entropy should be bytes or hex encoded string")
    if len(entropy) not in [16, 20, 24, 28, 32]:
        raise ValueError(
            'entropy length should be one of the following: [16, 20, 24, 28, 32]')
    if word_list is None:
        word_list = load_word_list(language, word_list_dir)
    elif not isinstance(word_list, list) or len(word_list) != 2048:
        raise TypeError("invalid word list type")

    i = int.from_bytes(entropy, byteorder="big")
    # append checksum
    i = (i << len(entropy) * 8 // 32) | sha256(entropy)[0]

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
    chk_sum = entropy_int & (2 ** chk_sum_bit_len - 1)
    entropy_int = entropy_int >> chk_sum_bit_len
    entropy = entropy_int.to_bytes((bit_size - chk_sum_bit_len) // 8, byteorder="big")
    if (sha256(entropy)[0] >> (8 - chk_sum_bit_len)) != chk_sum:
        raise ValueError("invalid mnemonic checksum")
    return entropy if not hex else entropy.hex()


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
