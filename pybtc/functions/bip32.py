from struct import pack
from pybtc.functions.key import private_to_public_key, private_key_to_wif
from pybtc.functions.hash import hmac_sha512, double_sha256, hash160
from pybtc.functions.encode import encode_base58, decode_base58
from pybtc.constants import *
from pybtc.crypto import __secp256k1_ec_pubkey_tweak_add__
from pybtc.functions.tools import get_bytes

def create_master_xprivate_key(seed, testnet=False, base58=None, hex=None):
    """
    Create extended private key from seed

    :param str,bytes key: seed HEX or bytes string. 
    :param boolean base58: (optional) return result as base58 encoded string, by default True.
    :param boolean hex: (optional) return result as HEX encoded string, by default False.
                        In case True base58 flag value will be ignored.
    :return: extended private key  in base58, HEX or bytes string format.
    """
    seed = get_bytes(seed)
    i = hmac_sha512(b"Bitcoin seed", seed)
    m, c = i[:32], i[32:]
    m_int = int.from_bytes(m, byteorder="big")

    if m_int <= 0 or m_int > ECDSA_SEC256K1_ORDER: # pragma: no cover
        return None
    prefix = TESTNET_XPRIVATE_KEY_PREFIX if testnet else MAINNET_XPRIVATE_KEY_PREFIX
    key = b''.join([prefix,
                    b'\x00\x00\x00\x00\x00\x00\x00\x00\x00',
                    c, b'\x00', m])
    if base58 is None and hex is None:
        base58 = True
    if base58:
        key = b"".join([key, double_sha256(key)[:4]])
        return encode_base58(key)
    else:
        if hex is None:
            hex = False
        return key if not hex else key.hex()


def xprivate_to_xpublic_key(xprivate_key, base58=True, hex=False):
    """
    Get extended public key from extended private key using ECDSA secp256k1

    :param str,bytes key: extended private key in base58, HEX or bytes string. 
    :param boolean base58: (optional) return result as base58 encoded string, by default True.
    :param boolean hex: (optional) return result as HEX encoded string, by default False.
                        In case True base58 flag value will be ignored.
    :return: extended public key  in base58, HEX or bytes string format.
    """
    if isinstance(xprivate_key, str):
        try:
            if len(xprivate_key) == 156:
                xprivate_key = bytes.fromhex(xprivate_key)
            else:
                xprivate_key = decode_base58(xprivate_key, checksum=True)
        except:
            raise ValueError("invalid extended private key")
    if not isinstance(xprivate_key, bytes):
        raise TypeError("extended private key should be base58 string or bytes")
    if xprivate_key[:4] == TESTNET_XPRIVATE_KEY_PREFIX:
        prefix = TESTNET_XPUBLIC_KEY_PREFIX
    elif xprivate_key[:4] == MAINNET_XPRIVATE_KEY_PREFIX:
        prefix = MAINNET_XPUBLIC_KEY_PREFIX
    elif xprivate_key[:4] == MAINNET_M49_XPRIVATE_KEY_PREFIX:
        prefix = MAINNET_M49_XPUBLIC_KEY_PREFIX
    elif xprivate_key[:4] == TESTNET_M49_XPRIVATE_KEY_PREFIX:
        prefix = TESTNET_M49_XPUBLIC_KEY_PREFIX
    elif xprivate_key[:4] == MAINNET_M84_XPRIVATE_KEY_PREFIX:
        prefix = MAINNET_M84_XPUBLIC_KEY_PREFIX
    elif xprivate_key[:4] == TESTNET_M84_XPRIVATE_KEY_PREFIX:
        prefix = TESTNET_M84_XPUBLIC_KEY_PREFIX
    else:
        raise ValueError("invalid extended private key")

    key = b"".join([prefix,
                    xprivate_key[4:45],
                    private_to_public_key(xprivate_key[46:], hex=False)])
    if hex:
        return key.hex()
    elif base58:
        key = b"".join([key, double_sha256(key)[:4]])
        return encode_base58(key)
    else:
        return key

def decode_path(path, sub_path=False):
    path = path.split('/')
    if not sub_path:
        if path[0] != 'm':
            raise ValueError("invalid path")


    r = []
    for k in path[1:]:
        if k[-1] == "'":
            k = int(k[:-1]) + HARDENED_KEY
        else:
            k = int(k)
        r.append(k)
    return r




def derive_xkey(xkey, path, base58=None, hex=None, sub_path=False):
    """
    Child Key derivation for extended private/public keys
    
    :param bytes xkey: extended private/public in base58, HEX or bytes string format.
    :param list path_level: list of derivation path levels. For hardened derivation use HARDENED_KEY flag.
    :param boolean base58: (optional) return result as base58 encoded string, by default True.
    :param boolean hex: (optional) return result as HEX encoded string, by default False.
                        In case True base58 flag value will be ignored.
    :return: extended child private/public key  in base58, HEX or bytes string format.
    """
    if isinstance(path, str):
        path = decode_path(path, sub_path = sub_path)
    if isinstance(xkey, str):
        xkey = decode_base58(xkey, checksum=True)
    key_type = xkey_type(xkey)


    if key_type == 'private':
        for i in path:
            xkey = derive_child_xprivate_key(xkey, i)

    elif key_type == 'public':
        for i in path:
            xkey = derive_child_xpublic_key(xkey, i)
    else:
        raise ValueError("invalid extended key")

    if base58 is None and hex is None:
        base58 = True
        hex = False

    if hex:
        return xkey.hex()
    elif base58:
        return encode_base58(xkey, checksum=True)
    else:
        return xkey


def derive_child_xprivate_key(xprivate_key, i):
    c = xprivate_key[13:45]
    k = xprivate_key[45:]
    depth = xprivate_key[4] + 1

    if depth > 255:
        raise ValueError("path depth should be <= 255")  # pragma: no cover
    pub = private_to_public_key(k[1:], hex=False)
    fingerprint = hash160(pub)[:4]
    s = hmac_sha512(c, b"%s%s" % (k if i >= HARDENED_KEY else pub, pack(">L", i)))
    p_int = int.from_bytes(s[:32],byteorder='big')
    if p_int >= ECDSA_SEC256K1_ORDER: # pragma: no cover
        return None
    k_int = (int.from_bytes(k[1:], byteorder='big') + p_int) % ECDSA_SEC256K1_ORDER
    if not k_int: # pragma: no cover
        return None
    key = int.to_bytes(k_int, byteorder = "big", length=32)
    return b"".join([xprivate_key[:4],
                     bytes([depth]),
                     fingerprint,
                     pack(">L", i),
                     s[32:],
                     b'\x00',
                     key])


def derive_child_xpublic_key(xpublic_key, i):
    c = xpublic_key[13:45]
    k = xpublic_key[45:]
    fingerprint = hash160(k)[:4]
    depth = xpublic_key[4] + 1
    if depth > 255:
        raise ValueError("path depth should be <= 255")   # pragma: no cover
    if i >= HARDENED_KEY:
        raise ValueError("derivation from extended public key impossible")
    s = hmac_sha512(c, k + pack(">L", i))
    if int.from_bytes(s[:32], byteorder='big') >= ECDSA_SEC256K1_ORDER: # pragma: no cover
        return None

    pk = __secp256k1_ec_pubkey_tweak_add__(k, s[:32])
    if isinstance(pk, int): # pragma: no cover
        raise RuntimeError("pubkey_tweak_add error %s" %pk)
    return b"".join([xpublic_key[:4],
                     bytes([depth]),
                     fingerprint,
                     pack(">L", i),
                     s[32:],
                     pk])


def public_from_xpublic_key(xpublic_key, hex=True):
    """
    Get public key from extended public key

    :param bytes xpublic_key: extended public in base58, HEX or bytes string format.
    :param boolean base58: (optional) return result as base58 encoded string, by default True.
    :param boolean hex: (optional) return result as HEX encoded string, by default False.
                        In case True base58 flag value will be ignored.
    :return: public key  in HEX or bytes string format.
    """
    if isinstance(xpublic_key, str):
        if len(xpublic_key) == 156:
            xpublic_key = bytes.fromhex(xpublic_key)
        else:
            xpublic_key = decode_base58(xpublic_key, checksum=True)
    if not isinstance(xpublic_key, bytes):
        raise TypeError("xpublic_key should be HEX, Base58 or bytes string")
    if xpublic_key[:4] not in [MAINNET_XPUBLIC_KEY_PREFIX,
                               TESTNET_XPUBLIC_KEY_PREFIX]:
        raise ValueError("invalid extended public key")

    return xpublic_key[45:].hex() if hex else xpublic_key[45:]


def private_from_xprivate_key(xprivate_key, wif=True, hex=False):
    """
    Get private key from extended private key

    :param bytes xprivate_key: extended public in base58, HEX or bytes string format.
    :param boolean wif: (optional) return result as WIF format, by default True.
    :param boolean hex: (optional) return result as HEX encoded string, by default False.
                        In case True WIF flag value will be ignored.
    :return: private key  in HEX or bytes string format.
    """
    if isinstance(xprivate_key, str):
        if len(xprivate_key) == 156:
            xprivate_key = bytes.fromhex(xprivate_key)
        else:
            xprivate_key = decode_base58(xprivate_key, checksum=True)
    if not isinstance(xprivate_key, bytes):
        raise TypeError("xprivate_key should be HEX, Base58 or bytes string")

    prefix = xprivate_key[:4]

    if prefix in (MAINNET_XPRIVATE_KEY_PREFIX,
                  MAINNET_M44_XPRIVATE_KEY_PREFIX,
                  MAINNET_M49_XPRIVATE_KEY_PREFIX,
                  MAINNET_M84_XPRIVATE_KEY_PREFIX):
        testnet = False
    elif prefix in (TESTNET_XPRIVATE_KEY_PREFIX,
                    TESTNET_M44_XPRIVATE_KEY_PREFIX,
                    TESTNET_M49_XPRIVATE_KEY_PREFIX,
                    TESTNET_M84_XPRIVATE_KEY_PREFIX):
        testnet = True
    else:
        raise ValueError("invalid extended private key")

    if hex:
        return xprivate_key[46:].hex()
    elif wif:
        return private_key_to_wif(xprivate_key[46:], testnet=testnet)
    return xprivate_key[46:].hex() if hex else xprivate_key[46:]


def is_xprivate_key_valid(key):
    """
    Check the extended private key is valid according to BIP-0032.

    :param key: extended private key in BASE58, HEX or bytes string format.
    :return: boolean.
    """
    if isinstance(key, str):
        try:
            key = decode_base58(key, checksum=True)
        except:
            try:
                key = bytes.fromhex(key)
            except:
                pass
    if not isinstance(key, bytes) or len(key)!=78:
        return False
    if key[:4] not in [MAINNET_XPRIVATE_KEY_PREFIX,
                       TESTNET_XPRIVATE_KEY_PREFIX,
                       MAINNET_M49_XPRIVATE_KEY_PREFIX,
                       TESTNET_M49_XPRIVATE_KEY_PREFIX,
                       MAINNET_M84_XPRIVATE_KEY_PREFIX,
                       TESTNET_M84_XPRIVATE_KEY_PREFIX]:
        return False
    return True


def is_xpublic_key_valid(key):
    """
    Check the extended private key is valid according to BIP-0032.

    :param key: extended private key in BASE58, HEX or bytes string format.
    :return: boolean.
    """
    if isinstance(key, str):
        try:
            key = decode_base58(key, verify_checksum = True)
        except:
            try:
                key = bytes.fromhex(key)
            except:
                pass
    if not isinstance(key, bytes) or len(key)!=78:
        return False

    if key[:4] not in [MAINNET_XPUBLIC_KEY_PREFIX,
                       TESTNET_XPUBLIC_KEY_PREFIX,
                       MAINNET_M49_XPUBLIC_KEY_PREFIX,
                       TESTNET_M49_XPUBLIC_KEY_PREFIX,
                       MAINNET_M84_XPUBLIC_KEY_PREFIX,
                       TESTNET_M84_XPUBLIC_KEY_PREFIX]:
        return False
    return True

def xkey_derivation_type(key):
    if isinstance(key, str):
        key = decode_base58(key, checksum=True)
    if len(key) != 78:
        return False
    prefix = key[:4]
    if prefix in (MAINNET_XPRIVATE_KEY_PREFIX, TESTNET_XPRIVATE_KEY_PREFIX,
                  MAINNET_XPUBLIC_KEY_PREFIX, TESTNET_XPUBLIC_KEY_PREFIX):
        return "BIP44"
    if prefix in (MAINNET_M49_XPRIVATE_KEY_PREFIX, TESTNET_M49_XPRIVATE_KEY_PREFIX,
                  MAINNET_M49_XPUBLIC_KEY_PREFIX, TESTNET_M49_XPUBLIC_KEY_PREFIX):
        return "BIP49"
    if prefix in (MAINNET_M84_XPRIVATE_KEY_PREFIX, TESTNET_M84_XPRIVATE_KEY_PREFIX,
                  MAINNET_M84_XPUBLIC_KEY_PREFIX, TESTNET_M84_XPUBLIC_KEY_PREFIX):
        return "BIP84"
    return "custom"


def xkey_network_type(key):
    if isinstance(key, str):
        key = decode_base58(key, checksum=True)
    if len(key) != 78:
        raise Exception("invalid extended key")
    prefix = key[:4]
    if prefix in (MAINNET_XPRIVATE_KEY_PREFIX, MAINNET_M49_XPRIVATE_KEY_PREFIX,
                  MAINNET_M84_XPRIVATE_KEY_PREFIX, MAINNET_XPUBLIC_KEY_PREFIX,
                  MAINNET_M49_XPUBLIC_KEY_PREFIX, MAINNET_M84_XPUBLIC_KEY_PREFIX):
        return "mainnet"
    if prefix in (TESTNET_XPRIVATE_KEY_PREFIX, TESTNET_M49_XPRIVATE_KEY_PREFIX,
                  TESTNET_M84_XPRIVATE_KEY_PREFIX, TESTNET_XPUBLIC_KEY_PREFIX,
                  TESTNET_M49_XPUBLIC_KEY_PREFIX, TESTNET_M84_XPUBLIC_KEY_PREFIX):
        return "testnet"
    raise Exception("invalid extended key")

def xkey_type(key):
    if isinstance(key, str):
        key = decode_base58(key, checksum=True)
    if len(key) != 78:
        raise Exception("invalid extended key")
    prefix = key[:4]
    if prefix in (MAINNET_XPRIVATE_KEY_PREFIX, MAINNET_M49_XPRIVATE_KEY_PREFIX,
                  MAINNET_M84_XPRIVATE_KEY_PREFIX, TESTNET_XPRIVATE_KEY_PREFIX,
                  TESTNET_M49_XPRIVATE_KEY_PREFIX, TESTNET_M84_XPRIVATE_KEY_PREFIX):
        return "private"
    if prefix in (MAINNET_XPUBLIC_KEY_PREFIX, MAINNET_M49_XPUBLIC_KEY_PREFIX,
                  MAINNET_M84_XPUBLIC_KEY_PREFIX, TESTNET_XPUBLIC_KEY_PREFIX,
                  TESTNET_M49_XPUBLIC_KEY_PREFIX, TESTNET_M84_XPUBLIC_KEY_PREFIX):
        return "public"
    raise ValueError("invalid extended key")

def path_xkey_to_bip32_xkey(key, base58=True, hex=False):
    if isinstance(key, str):
        try:
            key = decode_base58(key, verify_checksum = True)
        except:
            try:
                key = bytes.fromhex(key)
            except:
                pass

    if not isinstance(key, bytes) or len(key)!=78:
        raise ValueError("invalid extended key")

    if key[:4] in (MAINNET_XPUBLIC_KEY_PREFIX,
                   TESTNET_XPUBLIC_KEY_PREFIX,
                   MAINNET_XPRIVATE_KEY_PREFIX,
                   TESTNET_XPRIVATE_KEY_PREFIX):
        pass
    elif key[:4] in (MAINNET_M49_XPUBLIC_KEY_PREFIX, MAINNET_M84_XPUBLIC_KEY_PREFIX):
        key = MAINNET_XPUBLIC_KEY_PREFIX + key[4:]
    elif key[:4] in (TESTNET_M49_XPUBLIC_KEY_PREFIX, TESTNET_M84_XPUBLIC_KEY_PREFIX):
        key = TESTNET_XPUBLIC_KEY_PREFIX + key[4:]
    elif key[:4] in (MAINNET_M49_XPRIVATE_KEY_PREFIX, MAINNET_M84_XPRIVATE_KEY_PREFIX):
        key = MAINNET_XPRIVATE_KEY_PREFIX + key[4:]
    elif key[:4] in (TESTNET_M49_XPRIVATE_KEY_PREFIX, TESTNET_M84_XPRIVATE_KEY_PREFIX):
        key = TESTNET_XPRIVATE_KEY_PREFIX + key[4:]
    else:
        raise ValueError("invalid extended key")

    if hex:
        return key.hex()
    elif base58:
        return encode_base58(key, checksum=True)
    else:
        return key

def bip32_xkey_to_path_xkey(key, path_type, base58=True, hex=False):
    if path_type not in ("BIP44", "BIP49", "BIP84"):
        raise ValueError("unsupported path type %s" % path_type)

    if isinstance(key, str):
        try:
            key = decode_base58(key, verify_checksum = True)
        except:
            try:
                key = bytes.fromhex(key)
            except:
                pass
    if not isinstance(key, bytes) or len(key) != 78:
        raise ValueError("invalid key")

    if key[:4] == TESTNET_XPRIVATE_KEY_PREFIX:
        if path_type == "BIP44":
            key = TESTNET_M44_XPRIVATE_KEY_PREFIX + key[4:]
        elif path_type == "BIP49":
            key = TESTNET_M49_XPRIVATE_KEY_PREFIX + key[4:]
        else:
            key = TESTNET_M84_XPRIVATE_KEY_PREFIX + key[4:]

    elif key[:4] == MAINNET_XPRIVATE_KEY_PREFIX:
        if path_type == "BIP44":
            key = MAINNET_M44_XPRIVATE_KEY_PREFIX + key[4:]
        elif path_type == "BIP49":
            key = MAINNET_M49_XPRIVATE_KEY_PREFIX + key[4:]
        else:
            key = MAINNET_M84_XPRIVATE_KEY_PREFIX + key[4:]

    elif key[:4] == TESTNET_XPUBLIC_KEY_PREFIX:
        if path_type == "BIP44":
            key = TESTNET_M44_XPUBLIC_KEY_PREFIX + key[4:]
        elif path_type == "BIP49":
            key = TESTNET_M49_XPUBLIC_KEY_PREFIX + key[4:]
        else:
            key = TESTNET_M84_XPUBLIC_KEY_PREFIX + key[4:]

    elif key[:4] == MAINNET_XPUBLIC_KEY_PREFIX:
        if path_type == "BIP44":
            key = MAINNET_M44_XPUBLIC_KEY_PREFIX + key[4:]
        elif path_type == "BIP49":
            key = MAINNET_M49_XPUBLIC_KEY_PREFIX + key[4:]
        else:
            key = MAINNET_M84_XPUBLIC_KEY_PREFIX + key[4:]
    else:
        raise ValueError("invalid extended key")

    if hex:

        return key.hex()
    elif base58:
        return encode_base58(key, checksum = True)
    else:
        return key

