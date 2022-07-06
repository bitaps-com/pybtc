from struct import unpack
from pybtc.functions import *


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
    def __init__(self, init_vector=None,
                       passphrase="",
                       path=None,
                       strength=256,
                       threshold=1,
                       shares=1,
                       word_list=None,
                       address_type=None,
                       hardened_addresses=False,
                       account=0,
                       chain=0,
                       testnet=False):
        self.account = account
        self.chain = chain
        self.hardened_addresses = hardened_addresses
        self.passphrase = passphrase

        if address_type in (None, "P2PKH", "P2SH_P2WPKH", "P2WPKH"):
            self.address_type = address_type
        else:
            raise ValueError("unsupported address type %s" % address_type)
        self.path_type = None
        self.seed = None
        self.mnemonic = None
        self._init_vector = None
        self.master_private_xkey = None
        self.account_public_xkey = None
        self.account_private_xkey = None
        self.external_chain_private_xkey = None
        self.external_chain_private_xkey = None
        self.internal_chain_public_xkey = None
        self.internal_chain_public_xkey = None
        self.chain_private_xkey = None
        self.chain_public_xkey = None


        if path == "BIP84":
            self.path_type = "BIP84"
            self.path = "m/84'/0'/%s'/%s" % (self.account, self.chain)
            self._account_path =  "m/84'/0'/%s'" % self.account
        elif path == "BIP49":
            self.path_type = "BIP49"
            self.path = "m/49'/0'/%s'/%s" % (self.account, self.chain)
            self._account_path =  "m/49'/0'/%s'" % self.account
        elif path == "BIP44":
            self.path_type = "BIP44"
            self.path = "m/44'/0'/%s'/%s" % (self.account, self.chain)
            self._account_path =  "m/44'/0'/%s'" % self.account
        elif isinstance(path, str):
            self.path_type = "custom"
            self.path = path

        if isinstance(init_vector, list):
            for l in init_vector:
                if not is_mnemonic_valid(l):
                    break
            else:
                init_vector = combine_mnemonic(init_vector)

        if init_vector == None:
            self.mnemonic = entropy_to_mnemonic(generate_entropy(strength=strength), word_list=word_list)
            self.seed = mnemonic_to_seed(self.mnemonic, passphrase=passphrase)
            init_vector = create_master_xprivate_key(self.seed, testnet=testnet)
            if self.path_type is None:
                self.path_type = "BIP84"
                self.path = "m/84'/0'/%s'/%s" % (self.account, self.chain)
                self._account_path = "m/84'/0'/%s'" % self.account
            if self.path_type != "custom":
                init_vector = bip32_xkey_to_path_xkey(init_vector, self.path_type)
            init_vector_type = "xPriv"
        elif isinstance(init_vector, str):
            if is_xprivate_key_valid(init_vector):
                if self.path_type is None:
                    self.path_type = xkey_derivation_type(init_vector)
                    if self.path_type == "BIP84":
                        self.path = "m/84'/0'/%s'/%s" % (self.account, self.chain)
                        self._account_path = "m/84'/0'/%s'" % self.account
                    elif self.path_type == "BIP49":
                        self.path = "m/49'/0'/%s'/%s" % (self.account, self.chain)
                        self._account_path = "m/49'/0'/%s'" % self.account
                    elif self.path_type == "BIP44":
                        self.path = "m/44'/0'/%s'/%s" % (self.account, self.chain)
                        self._account_path = "m/44'/0'/%s'" % self.account
                    else:
                        self.path = "m"
                elif self.path_type != "custom":
                    init_vector = bip32_xkey_to_path_xkey(init_vector, self.path_type)
                init_vector_type = "xPriv"

            elif is_xpublic_key_valid(init_vector):
                if self.path_type is None:
                    self.path_type = xkey_derivation_type(init_vector)
                    if self.path_type == "BIP84":
                        self.path = "m/84'/0'/%s'/%s" % (self.account, self.chain)
                        self._account_path = "m/84'/0'/%s'" % self.account
                    elif self.path_type == "BIP49":
                        self.path = "m/49'/0'/%s'/%s" % (self.account, self.chain)
                        self._account_path = "m/49'/0'/%s'" % self.account
                    elif self.path_type == "BIP44":
                        self.path = "m/44'/0'/%s'/%s" % (self.account, self.chain)
                        self._account_path = "m/44'/0'/%s'" % self.account
                    else:
                        self.path = "m"
                elif self.path_type != "custom":
                    init_vector = bip32_xkey_to_path_xkey(init_vector, self.path_type)
                init_vector_type = "xPub"

            else:
                if not is_mnemonic_valid(init_vector):
                    raise Exception("Invalid mnemonic")
                self.mnemonic = init_vector
                self.seed = mnemonic_to_seed(self.mnemonic, passphrase=passphrase)
                init_vector = create_master_xprivate_key(self.seed, testnet=testnet)
                if self.path_type is None:
                    self.path_type = "BIP84"
                    self.path = "m/84'/0'/%s'/%s" % (self.account, self.chain)
                    self._account_path = "m/84'/0'/%s'" % self.account

                if self.path_type != "custom":
                    init_vector = bip32_xkey_to_path_xkey(init_vector, self.path_type)
                init_vector_type = "xPriv"
        else:
            raise Exception("invalid initial data")

        raw_init_vector = decode_base58(init_vector, checksum=True)
        self.testnet = xkey_network_type(raw_init_vector) == 'testnet'
        self.version = raw_init_vector[:4].hex()
        self.depth = unpack('B', raw_init_vector[4:5])[0]
        if self.path_type != 'custom':
            if self.depth == 0 or self.depth == 3:
                l = self.path.split('/')
                self._path = '/'.join(l[self.depth:4])
            else:
                self.path_type = 'custom'
                self.path = 'm'

        self.fingerprint = raw_init_vector[5:9].hex()
        self.child = unpack('I', raw_init_vector[9:13])[0]
        self.chain_code = raw_init_vector[13:45].hex()
        if init_vector_type == "xPriv":
            if self.depth == 0:
                self.master_private_xkey = init_vector

            if self.path_type != 'custom':
                self.account_private_xkey = derive_xkey(init_vector, self._path, sub_path=True)
                self.account_public_xkey = xprivate_to_xpublic_key(self.account_private_xkey)
                self.external_chain_private_xkey =  derive_xkey(init_vector, "%s/%s" % (self._path, self.chain),
                                                                sub_path=True)
                self.external_chain_public_xkey = xprivate_to_xpublic_key(self.external_chain_private_xkey)

                self.internal_chain_private_xkey =  derive_xkey(init_vector, "%s/%s" % (self._path, self.chain + 1),
                                                                sub_path=True)
                self.internal_chain_public_xkey = xprivate_to_xpublic_key(self.internal_chain_private_xkey)
            else:
                self.chain_private_xkey = derive_xkey(init_vector, self.path)
                self.chain_public_xkey = xprivate_to_xpublic_key(self.chain_private_xkey)
        else:
            if self.path_type != 'custom':
                self.account_public_xkey = init_vector
                self.external_chain_public_xkey = derive_xkey(init_vector, "%s/%s" % (self._path, self.chain),
                                                                sub_path=True)
                self.internal_chain_public_xkey = derive_xkey(init_vector, "%s/%s" % (self._path, self.chain + 1),
                                                                sub_path=True)
            else:
                self.chain_public_xkey = derive_xkey(init_vector, self.path)

        if self.mnemonic is not None:
            self.shares_threshold = threshold
            self.shares_total = shares
            if self.shares_threshold > self.shares_total:
                raise Exception("Shares threshold  invalid")
            if self.shares_total > 1:
                m = self.mnemonic.split()
                bit_size = len(m) * 11
                check_sum_bit_len = bit_size % 32
                if self.shares_total > (2 ** check_sum_bit_len - 1):
                    raise Exception("Maximum %s shares "
                                    "allowed for %s mnemonic words" % (2 ** check_sum_bit_len - 1, len(m)))
                self.mnemonic_shares = split_mnemonic(self.mnemonic, self.shares_threshold, self.shares_total,
                                                      embedded_index=True, word_list=word_list)


        if address_type is None:
            if self.path_type == "BIP84":
                self.address_type = "P2WPKH"
            elif self.path_type == "BIP49":
                self.address_type = "P2SH_P2WPKH"
            else:
                self.address_type = "P2PKH"


    def get_address(self, i, external=True, address_type=None):
        iq = str(i)
        if self.hardened_addresses:
            i = i|HARDENED_KEY
            iq = "%s'" % i
        if self.path_type != "custom":
            if external:
                path = self.path
                if self.external_chain_private_xkey:
                    key = derive_xkey(path_xkey_to_bip32_xkey(self.external_chain_private_xkey), [i])
                    private_key = private_from_xprivate_key(key)
                    pub_key = private_to_public_key(private_key)
                else:
                    key = derive_xkey(path_xkey_to_bip32_xkey(self.external_chain_public_xkey), [i])
                    pub_key = public_from_xpublic_key(key)
                    private_key = None
            else:
                if self.internal_chain_private_xkey:
                    key = derive_xkey(path_xkey_to_bip32_xkey(self.internal_chain_private_xkey), [i])
                    private_key = private_from_xprivate_key(key)
                    pub_key = private_to_public_key(private_key)
                else:
                    key = derive_xkey(path_xkey_to_bip32_xkey(self.internal_chain_public_xkey), [i])
                    pub_key = public_from_xpublic_key(key)
                    private_key = None
            path = "%s/%s/%s" % (self._path, self.chain, iq)
        else:
            if self.chain_private_xkey:
                key = derive_xkey(path_xkey_to_bip32_xkey(self.chain_private_xkey), [i])
                private_key = private_from_xprivate_key(key)
                pub_key = private_to_public_key(private_key)
            else:
                key = derive_xkey(path_xkey_to_bip32_xkey(self.chain_public_xkey), [i])
                pub_key = public_from_xpublic_key(key)
                private_key = None
            path = "%s/%s" % (self.path, iq)
        if address_type is None:
            address_type = self.address_type

        if address_type == "P2WPKH":
            address = public_key_to_address(pub_key, testnet=self.testnet)
        elif address_type == "P2SH_P2WPKH":
            address = public_key_to_address(pub_key, p2sh_p2wpkh=True, testnet=self.testnet)
        else:
            address = public_key_to_address(pub_key, witness_version=None, testnet=self.testnet)



        if private_key:
            r = {"address": address, "public_key": pub_key, "private_key": private_key, "path": path}
        else:
            r = {"address": address, "public_key": pub_key, "path": path}
        return r




