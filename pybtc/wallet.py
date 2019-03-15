from struct import unpack
from .functions import *


# Hierarchical Deterministic Wallets (HD Wallets)
# BIP-44 support

class Wallet():
    """
    The class for creating wallet object.

    :param init_vector: (optional) initialization vector should be mnemonic phrase, extended public key,
                        extended private key, by default None (generate new wallet).
    :param compressed: (optional) if set to True private key corresponding compressed public key,
                       by default set to True. Recommended use only compressed public key.
    :param testnet: (optional) if set to True mean that this private key for testnet Bitcoin network.

    """
    def __init__(self, init_vector=None, passphrase="", language='english', word_list_dir=None, word_list=None):
        if init_vector is None:
            e = generate_entropy()
            m = entropy_to_mnemonic(e)
            self.mnemonic = m
            init_vector = create_master_xprivate_key(mnemonic_to_seed(m), base58=False)
        else:
            if isinstance(init_vector, str):
                if is_xprivate_key_valid(init_vector):
                    if len(init_vector) == 156:
                        init_vector = bytes.fromhex(init_vector)
                    else:
                        init_vector = decode_base58_with_checksum(init_vector)
                elif is_xpublic_key_valid(init_vector):
                    if len(init_vector) == 156:
                        init_vector = bytes.fromhex(init_vector)
                    else:
                        init_vector = decode_base58_with_checksum(init_vector)
                else:
                    try:
                        self.mnemonic = init_vector
                        self.passphrase = passphrase
                        init_vector = create_master_xprivate_key(mnemonic_to_seed(init_vector,
                                                                                  passphrase=passphrase),
                                                                 base58=False)
                    except Exception as err:
                        raise ValueError("invalid initial vector %s" % err)
        if not isinstance(init_vector, bytes):
            raise ValueError("invalid initial vector")
        self.accounts = dict()
        self.extended_key = self.deserialize_xkey(init_vector)

    def deserialize_xkey(self, xkey):
        if isinstance(xkey, str):
            xkey = decode_base58_with_checksum(xkey)
        extended_key = dict()
        extended_key['version'] = xkey[:4].hex()
        extended_key['depth'] = unpack('B', xkey[4:5])[0]
        extended_key['fingerprint'] = xkey[5:9].hex()
        extended_key['child'] = unpack('I', xkey[9:13])[0]
        extended_key['chain_code'] = xkey[13:45].hex()
        info = ["Derived"] if extended_key['depth'] != 0 else ["Master"]
        if xkey[:4] in [MAINNET_XPRIVATE_KEY_PREFIX, MAINNET_XPUBLIC_KEY_PREFIX]:
            info.append("Mainnet")
            extended_key["testnet"] = False
        else:
            info.append("Testnet")
            extended_key["testnet"] = True
        info.append("Extended")
        if xkey[:4] in [MAINNET_XPRIVATE_KEY_PREFIX, TESTNET_XPRIVATE_KEY_PREFIX]:
            testnet = False if xkey[:4] == MAINNET_XPRIVATE_KEY_PREFIX else True
            extended_key['private_key'] = private_key_to_wif(xkey[46:78], testnet=testnet)
            info.append("Private")
            extended_key["type"] = "private"
        else:
            info.append("Public")
            extended_key['public_key'] = xkey[45:78].hex()
            extended_key["type"] = "public"

        info.append("Key")
        extended_key["info"] = " ".join(info)
        extended_key["key"] = encode_base58_with_checksum(xkey)
        return extended_key

    def create_account(self,name, path):
        self.accounts[name] = {"extended_key": self.deserialize_xkey(derive_xkey(self.extended_key["key"],
                                                                                 *path)),
                               "path": path}

    def create_bip44_account(self, account=0):
        if self.extended_key["depth"] != 0:
            raise Exception("Create bip44 account only possible from Master private key")
        if not isinstance(account, int):
            raise  ValueError("account should be integer")
        self.create_account("%s_external" % account, [44|HARDENED_KEY, HARDENED_KEY, account, 0])
        self.create_account("%s_internal" % account, [44|HARDENED_KEY, HARDENED_KEY, account, 1])

    def get_bip44_address(self, i, chain="external", account_index=0, address_type="P2WPKH"):
        if chain not in ("internal", "external"):
            raise ValueError("chain should be inetrnal or external")
        account_name = "%s_%s" % (account_index, chain)
        if account_name not in self.accounts:
            self.create_bip44_account(account=account_index)
        return self.get_chain_address(i, account=account_name, address_type=address_type)

    def get_chain_address(self, i, account=None, address_type="P2WPKH"):
        if account is None:
            xkey = self.extended_key["key"]
            key_type = self.extended_key["type"]
            testnet = self.extended_key["testnet"]
        else:
            xkey = self.accounts[account]["extended_key"]["key"]
            key_type = self.accounts[account]["extended_key"]["type"]
            testnet = self.accounts[account]["extended_key"]["testnet"]
        xkey = derive_xkey(xkey, i)
        if key_type == "public":
            address = public_key_to_address(public_from_xpublic_key(xkey), testnet=testnet)
            r = {"address": address,
                 "public_key": public_from_xpublic_key(xkey)}
        elif key_type == "private":
            private_key = private_from_xprivate_key(xkey)
            if address_type == "P2WPKH":
                address = public_key_to_address(private_to_public_key(private_key), testnet=testnet)
            elif address_type == "P2SH_P2WPKH":
                address = public_key_to_address(private_to_public_key(private_key), p2sh_p2wpkh=True,
                                                testnet=testnet)
            elif address_type == "P2PKH":
                address = public_key_to_address(private_to_public_key(private_key), witness_version=None,
                                                testnet=testnet)
            r = {"address": address,
                 "public_key": private_to_public_key(private_key),
                 "private_key": private_key}
        return r


