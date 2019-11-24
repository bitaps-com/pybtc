from struct import unpack
from .functions import *


# Hierarchical Deterministic Wallets (HD Wallets)
# BIP-44 BIP-49 BIP-84

class Wallet():
    """
    The class for creating wallet object.

    :param init_vector: (optional) initialization vector should be mnemonic phrase, extended public key,
                        extended private key, by default None (generate new wallet).
    :param compressed: (optional) if set to True private key corresponding compressed public key,
                       by default set to True. Recommended use only compressed public key.
    :param testnet: (optional) if set to True mean that this private key for testnet Bitcoin network.

    """
    def __init__(self, init_vector=None, passphrase="", path_type=None,
                 init_account=None, address_type=None, testnet=False, hardened=False):
        self.seed = None
        self.mnemonic = None
        self._init_vector = None
        self.account_public_xkey = None
        self.account_private_xkey = None
        self.external_chain_private_xkey = None
        self.external_chain_private_xkey = None
        self.internal_chain_public_xkey = None
        self.internal_chain_public_xkey = None
        self.hardened = hardened

        if path_type in (None, "BIP44", "BIP49", "BIP84"):
            self.path_type = path_type
        else:
            raise ValueError("unknown path type %s" % path_type)

        if address_type in (None, "P2PKH", "P2SH_P2WPKH", "P2WPKH"):
            self.address_type = address_type
        else:
            raise ValueError("unsupported address type %s" % address_type)

        self.account = 0
        if init_account is not None:
            self.account = int(init_account)

        if init_vector is None:
            e = generate_entropy()
            m = entropy_to_mnemonic(e)
            self.mnemonic = m
            self.seed = mnemonic_to_seed(m)
            self._init_vector = create_master_xprivate_key(self.seed, base58=False, testnet=testnet)
            self._init_vector_type = "xprivate_key"
        else:
            if isinstance(init_vector, str):
                if is_xprivate_key_valid(init_vector):
                    if len(init_vector) == 156:
                        self._init_vector = bytes.fromhex(init_vector)
                    else:
                        self._init_vector = decode_base58_with_checksum(init_vector)
                    self._init_vector_type = "xprivate_key"

                    if path_type is None:
                        if self._init_vector[:4] in (MAINNET_M49_XPRIVATE_KEY_PREFIX,
                                                          TESTNET_M49_XPRIVATE_KEY_PREFIX):
                            self.path_type = "BIP49"
                        elif self._init_vector[:4] in (MAINNET_M84_XPRIVATE_KEY_PREFIX,
                                                            TESTNET_M84_XPRIVATE_KEY_PREFIX):
                            self.path_type = "BIP84"
                        elif self._init_vector[:4] in (MAINNET_M44_XPRIVATE_KEY_PREFIX,
                                                            TESTNET_M44_XPRIVATE_KEY_PREFIX):
                            self.path_type = "BIP44"

                elif is_xpublic_key_valid(init_vector):
                    if len(init_vector) == 156:
                        self._init_vector = bytes.fromhex(init_vector)
                    else:
                        self._init_vector = decode_base58_with_checksum(init_vector)
                    self._init_vector_type = "xpublic_key"
                    if path_type is None:
                        if self._init_vector[:4] in (MAINNET_M49_XPUBLIC_KEY_PREFIX,
                                                          TESTNET_M49_XPUBLIC_KEY_PREFIX):
                            self.path_type = "BIP49"
                        elif self._init_vector[:4] in (MAINNET_M84_XPUBLIC_KEY_PREFIX,
                                                            TESTNET_M84_XPUBLIC_KEY_PREFIX):
                            self.path_type = "BIP84"
                        elif self._init_vector[:4] in (MAINNET_M44_XPUBLIC_KEY_PREFIX,
                                                            TESTNET_M44_XPUBLIC_KEY_PREFIX):
                            self.path_type = "BIP44"
                else:
                    try:
                        self.mnemonic = init_vector
                        self.passphrase = passphrase
                        self.seed = mnemonic_to_seed(self.mnemonic, passphrase=passphrase)
                        self._init_vector = create_master_xprivate_key(self.seed, base58=False, testnet=testnet)
                        self._init_vector_type = "xprivate_key"
                    except Exception as err:
                        raise ValueError("invalid initial vector %s" % err)
        if not isinstance(self._init_vector, bytes):
            raise ValueError("invalid initial vector")


        if self._init_vector[:4] in (MAINNET_XPRIVATE_KEY_PREFIX, MAINNET_XPUBLIC_KEY_PREFIX,
                                     MAINNET_M49_XPUBLIC_KEY_PREFIX, MAINNET_M49_XPRIVATE_KEY_PREFIX,
                                     MAINNET_M84_XPUBLIC_KEY_PREFIX, MAINNET_M84_XPRIVATE_KEY_PREFIX):
            self.testnet = False
        else:
            self.testnet = True

        if self.path_type in ("BIP44", "BIP49", "BIP84"):
            if self.address_type is None:
                if self.path_type == "BIP44":
                    self.address_type = "P2PKH"
                    self.path = [44 | HARDENED_KEY, HARDENED_KEY, self.account | HARDENED_KEY]
                elif self.path_type == "BIP49":
                    self.address_type = "P2SH_P2WPKH"
                    self.path = [49 | HARDENED_KEY, HARDENED_KEY, self.account | HARDENED_KEY]
                elif self.path_type == "BIP84":
                    self.address_type = "P2WPKH"
                    self.path = [84 | HARDENED_KEY, HARDENED_KEY, self.account | HARDENED_KEY]

            self.version = self._init_vector[:4].hex()
            self.depth = unpack('B', self._init_vector[4:5])[0]
            if self.depth != 0:
                self.path = []
            self.fingerprint = self._init_vector[5:9].hex()
            self.child = unpack('I', self._init_vector[9:13])[0]
            self.chain_code = self._init_vector[13:45].hex()

            if self._init_vector_type == "xprivate_key":
                if self.mnemonic:
                    info = ["Mnemonic seed"]
                else:
                    info = ["Derived private key"] if self.depth != 0 else ["Master private key"]
                if self.testnet:
                    info.append("[Testnet]")
                else:
                    info.append("[Mainnet]")
                self.info = " ".join(info)

                self._init_vector = path_xkey_to_bip32_xkey(self._init_vector, base58=False)

                key = derive_xkey(self._init_vector, *(self.path))
                self.account_private_xkey = bip32_xkey_to_path_xkey(key, self.path_type)
                self.account_public_xkey = bip32_xkey_to_path_xkey(xprivate_to_xpublic_key(key), self.path_type)

                key = derive_xkey(self._init_vector, *(self.path + [0]))
                self.external_chain_private_xkey = bip32_xkey_to_path_xkey(key, self.path_type)
                self.external_chain_public_xkey = bip32_xkey_to_path_xkey(xprivate_to_xpublic_key(key), self.path_type)


                key = derive_xkey(self._init_vector, *(self.path + [1]))

                self.internal_chain_private_xkey = bip32_xkey_to_path_xkey(key, self.path_type)
                self.internal_chain_public_xkey = bip32_xkey_to_path_xkey(xprivate_to_xpublic_key(key), self.path_type)
            else:
                if self.mnemonic:
                    info = ["Mnemonic seed"]
                else:
                    info = ["Derived public key"] if self.depth != 0 else ["Master public key"]
                if self.testnet:
                    info.append("[Testnet]")
                else:
                    info.append("[Mainnet]")
                self.info = " ".join(info)

                self._init_vector = path_xkey_to_bip32_xkey(self._init_vector, base58=False)

                self.account_private_xkey = None
                self.account_public_xkey = bip32_xkey_to_path_xkey(self._init_vector, self.path_type)

                key = derive_xkey(self._init_vector, 0)
                self.external_chain_private_xkey = None
                self.external_chain_public_xkey = bip32_xkey_to_path_xkey(key, self.path_type)

                key = derive_xkey(self._init_vector, 1)
                self.internal_chain_private_xkey = None
                self.internal_chain_public_xkey = bip32_xkey_to_path_xkey(key, self.path_type)
        elif self.path_type == "Custom":
            pass
        elif self.path_type is None:
            pass
        else:
            raise ValueError("unknown path type %s" % path_type)

    def get_address(self, i, chain="external"):
        if chain not in ("external", "internal"):
            raise ValueError("invalid chain, should be [external, internal]")
        if self.hardened:
            i = i|HARDENED_KEY

        if chain == "external":
            if self.external_chain_private_xkey:
                key = derive_xkey(path_xkey_to_bip32_xkey(self.external_chain_private_xkey), i)
                private_key = private_from_xprivate_key(key)
                pub_key = private_to_public_key(private_key)
            else:
                key = derive_xkey(path_xkey_to_bip32_xkey(self.external_chain_public_xkey), i)
                pub_key = public_from_xpublic_key(key)
                private_key = None
        else:
            if self.internal_chain_private_xkey:
                key = derive_xkey(path_xkey_to_bip32_xkey(self.internal_chain_private_xkey), i)
                private_key = private_from_xprivate_key(key)
                pub_key = private_to_public_key(private_key)
            else:
                key = derive_xkey(path_xkey_to_bip32_xkey(self.internal_chain_public_xkey), i)
                pub_key = public_from_xpublic_key(key)
                private_key = None

        if self.address_type == "P2WPKH":
            address = public_key_to_address(pub_key, testnet=self.testnet)
        elif self.address_type == "P2SH_P2WPKH":
            address = public_key_to_address(pub_key, p2sh_p2wpkh=True, testnet=self.testnet)
        elif self.address_type == "P2PKH":
            address = public_key_to_address(pub_key, witness_version=None, testnet=self.testnet)

        if private_key:
            r = {"address": address, "public_key": pub_key, "private_key": private_key}
        else:
            r = {"address": address, "public_key": pub_key}
        return r




