from pybtc.constants import *
from pybtc.functions.encode import encode_base58, decode_base58
from pybtc.functions.hash import double_sha256
from .bip39_mnemonic import generate_entropy
bytes_from_hex = bytes.fromhex
from pybtc.crypto import __secp256k1_ec_pubkey_create__


def create_private_key(compressed=True, testnet=False, wif=None, hex=None):
    """
    Create private key

    :param compressed: (optional) Type of public key, by default set to compressed. 
                                 Using uncompressed public keys is deprecated in new SEGWIT addresses, 
                                 use this option only for backward compatibility.  
    :param testnet: (optional) flag for testnet network, by default is False.
    :param wif:  (optional) If set to True return key in WIF format, by default is True.
    :param hex:  (optional) If set to True return key in HEX format, by default is False.
    :return: Private key in wif format (default), hex encoded byte string in case of hex flag or
             raw bytes string in case wif and hex flags set to False.

    """
    if wif is None:
        if hex is None:
            wif = True
        else:
            wif = False

    if wif:
        return private_key_to_wif(generate_entropy(hex=False), compressed=compressed, testnet=testnet)
    elif hex:
        return generate_entropy()
    return generate_entropy(hex=False)


def private_key_to_wif(h, compressed=True, testnet=False):
    """
    Encode private key in HEX or RAW bytes format to WIF format.

    :param h: private key 32 byte string or HEX encoded string.
    :param compressed: (optional) flag of public key compressed format, by default set to True.  
    :param testnet: (optional) flag for testnet network, by default is False.
    :return: Private key in WIF format.
    """
    # uncompressed: 0x80 + [32-byte secret] + [4 bytes of Hash() of previous 33 bytes], base58 encoded.
    # compressed: 0x80 + [32-byte secret] + 0x01 + [4 bytes of Hash() previous 34 bytes], base58 encoded.
    if isinstance(h, str):
        h = bytes_from_hex(h)
    if len(h) != 32 and isinstance(h, bytes):
        raise TypeError("private key must be a 32 bytes or hex encoded string")
    if testnet:
        h = TESTNET_PRIVATE_KEY_BYTE_PREFIX + h
    else:
        h = MAINNET_PRIVATE_KEY_BYTE_PREFIX + h
    if compressed:
        h += b'\x01'
    h += double_sha256(h)[:4]
    return encode_base58(h)


def wif_to_private_key(h, hex=True):
    """
    Decode WIF private key to bytes string or HEX encoded string

    :param hex:  (optional) if set to True return key in HEX format, by default is True.
    :return: Private key HEX encoded string or raw bytes string.
    """
    h = decode_base58(h)
    if double_sha256(h[:-4])[:4] != h[-4:]:
        raise TypeError("invalid wif key")
    return h[1:33].hex() if hex else h[1:33]


def is_wif_valid(wif):
    """
    Check is private key in WIF format string is valid.

    :param wif: private key in WIF format string.
    :return: boolean.
    """
    if not isinstance(wif, str):
        return False
    if wif[0] not in PRIVATE_KEY_PREFIX_LIST:
        return False
    try:
        h = decode_base58(wif)
    except:
        return False
    checksum = h[-4:]
    if wif[0] in (MAINNET_PRIVATE_KEY_UNCOMPRESSED_PREFIX,
                  TESTNET_PRIVATE_KEY_UNCOMPRESSED_PREFIX):
        if len(h) != 37:
            return False
    elif len(h) != 38:
        return False
    if double_sha256(h[:-4])[:4] != checksum:
        return False
    return True


def private_to_public_key(private_key, compressed=True, hex=True):
    """
    Get public key from private key using ECDSA secp256k1

    :param private_key: private key in WIF, HEX or bytes.
    :param compressed: (optional) flag of public key compressed format, by default set to True.
                       In case private_key in WIF format, this flag is set in accordance with 
                       the key format specified in WIF string.
    :param hex:  (optional) if set to True return key in HEX format, by default is True.
    :return: 33/65 bytes public key in HEX or bytes string.
    """
    if not isinstance(private_key, bytes):
        if isinstance(private_key, bytearray):
            private_key = bytes(private_key)
        elif isinstance(private_key, str):
            try:
                if private_key[0] in (MAINNET_PRIVATE_KEY_UNCOMPRESSED_PREFIX,
                                      TESTNET_PRIVATE_KEY_UNCOMPRESSED_PREFIX):
                    compressed = False
                h = decode_base58(private_key)
                if double_sha256(h[:-4])[:4] != h[-4:]:
                    raise Exception()
                private_key = h[1:33]
            except:
                try:
                    private_key = bytes_from_hex(private_key)
                except:
                    raise ValueError("private key HEX or WIF invalid")
        else:
            raise ValueError("private key must be a bytes or WIF or hex encoded string")
        if len(private_key) != 32:
            raise ValueError("private key length invalid")
    pub = __secp256k1_ec_pubkey_create__(private_key, bool(compressed))
    return pub.hex() if hex else pub


def is_public_key_valid(key):
    """
    Check public key is valid.

    :param key: public key in HEX or bytes string format.
    :return: boolean.
    """
    if isinstance(key, str):
        try:
            key = bytes_from_hex(key)
        except:
            return False
    if len(key) < 33:
        return False
    elif key[0] == 0x04 and len(key) != 65:
        return False
    elif key[0] == 0x02 or key[0] == 0x03:
        if len(key) != 33:
            return False
    return not ((key[0] < 2 or key[0] > 4))
