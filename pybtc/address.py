from .tools import *


class PrivateKey():
    def __init__(self, key=None, compressed=True, testnet=False):
        if key is None:
            self.compressed = compressed
            self.testnet = testnet
            self.raw_key = create_private_key()
        else:
            if type(key) == str:
                try:
                    key = unhexlify(key)
                except:
                    pass
            if type(key) == bytes:
                assert len(key) == 32
                self.raw_key = key
                self.compressed = compressed
                self.testnet = testnet
                return
            assert type(key) == str
            self.raw_key = wif_to_private_key(key)
            if key[0] in (MAINNET_PRIVATE_KEY_UNCOMPRESSED_PREFIX,
                          TESTNET_PRIVATE_KEY_UNCOMPRESSED_PREFIX):
                self.compressed = False
            else:
                self.compressed = True
            if key[0] in (TESTNET_PRIVATE_KEY_UNCOMPRESSED_PREFIX,
                          TESTNET_PRIVATE_KEY_COMPRESSED_PREFIX):
                self.testnet = True
            else:
                self.testnet = False

    def hex(self):
        return hexlify(self.raw_key).decode()

    def wif(self, compressed=None, testnet=None):
        if compressed is None:
            compressed = self.compressed
        if testnet is None:
            testnet = self.testnet
        return private_key_to_wif(self.raw_key, compressed, testnet)

    def __str__(self):
        return self.wif()


class PublicKey():
    def __init__(self, key=None):
        if type(key) == str:
            try:
                key = unhexlify(key)
            except:
                pass
        if type(key) == PrivateKey:
            key = private_to_public_key(key.raw_key,
                                        compressed=key.compressed)
        assert type(key) == bytes
        assert len(key) == 33 or len(key) == 65
        if len(key) == 33:
            self.compressed = True
        else:
            self.compressed = False
        self.raw_key = key

    def hex(self):
        return hexlify(self.raw_key).decode()

    def __str__(self):
        return hex()


class Address():
    def __init__(self, key=None,
                 address_type="P2WPKH", testnet=False, compressed=True):
        if key is None:
            self.private_key = PrivateKey(testnet=testnet,
                                          compressed=compressed)
            self.public_key = PublicKey(self.private_key)
            self.testnet = testnet
        elif type(key) == PrivateKey:
            self.private_key = key
            self.testnet = key.testnet
            compressed = key.compressed
            self.public_key = PublicKey(self.private_key)
        elif type(key) == PublicKey:
            self.public_key = key
            self.testnet = testnet
            compressed = key.compressed
        assert address_type in ("P2PKH", "PUBKEY", "P2WPKH", "P2SH_P2WPKH")
        if not compressed:
            assert address_type in ("P2PKH", "PUBKEY")
        self.type = address_type

        if address_type in ("P2WPKH"):
            self.witness_version = 0
        else:
            self.witness_version = None
        self.compressed = compressed
        if address_type == "P2SH_P2WPKH":
            self.script_hash = True
            self.redeem_script_raw = public_key_to_p2sh_p2wpkh_script(self.public_key.raw_key)
            self.redeem_script = hexlify(self.redeem_script_raw).decode()
            self.hash = hash160(self.redeem_script_raw)
        else:
            self.script_hash = False
            self.hash = hash160(self.public_key.raw_key)
        self.address = hash_to_address(self.hash,
                                       script_hash=self.script_hash,
                                       witness_version=self.witness_version,
                                       testnet=self.testnet)

    def __str__(self):
        return self.address


class ScriptAddress():
    def __init__(self, script, address_type="P2SH",
                 testnet=False, witness_version=None):
        self.witness_version = witness_version
        self.testnet = testnet
        if type(script) == str:
            script = unhexlify(script)
        self.script_raw = script
        self.script = hexlify(self.script_raw).decode()
        self.hash = hash160(self.script_raw)
        self.script_opcodes = decode_script(self.script_raw)
        self.script_opcodes_asm = decode_script(self.script_raw, 1)
        self.address = hash_to_address(self.hash,
                                       script_hash=True,
                                       witness_version=self.witness_version,
                                       testnet=self.testnet)