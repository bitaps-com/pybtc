from .tools import *


class PrivateKey():
    """
    The class for creating private key object.

    :param key: (optional) private key in HEX,  bytes string or WIF format. In case no key specified
                new random private key will be created.
    :param compressed: (optional) if set to True private key corresponding compressed public key,
                       by default set to True. Recommended use only compressed public key.
    :param testnet: (optional) if set to True mean that this private key for testnet Bitcoin network.

    """
    def __init__(self, key=None, compressed=True, testnet=False):

        if key is None:

            #: flag for compressed type of corresponding public key (boolean)
            self.compressed = compressed
            #: flag for testnet network private key  (boolean)
            self.testnet = testnet

            #: private key in  bytes (bytes)
            self.key = create_private_key(wif=False)
            #: private key in HEX (string)
            self.hex = hexlify(self.key).decode()
            #: private key in WIF format (string)
            self.wif = private_key_to_wif(self.key, compressed, testnet)

        else:
            if isinstance(key, str):
                try:
                    key = unhexlify(key)
                except:
                    pass
            if isinstance(key, bytes):
                if len(key) != 32:
                    raise TypeError("private key invalid length")
                self.key = key
                self.compressed = compressed
                self.testnet = testnet
                self.hex = hexlify(self.key).decode()
                self.wif = private_key_to_wif(self.key, compressed, testnet)
                return
            assert isinstance(key, str)
            self.key = wif_to_private_key(key, hex=False)
            self.hex = hexlify(self.key).decode()
            self.wif = private_key_to_wif(self.key, compressed, testnet)
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

    def __str__(self):
        return self.wif


class PublicKey():
    """
    The class for public key object.

    :param key:  one of this types allowed:
    
                - private key is instance of ``PrivateKey`` class
                - private key HEX encoded string
                - private key 32 bytes string
                - private key in WIF format
                - public key in HEX encoded string
                - public key [33/65] bytes string
                
                In case no key specified with HEX or bytes string you have to provide flag for testnet 
                and compressed key. WIF format and ``PrivateKey`` instance already contain this flags.
                For HEX or bytes public key only testnet flag has the meaning, comressed flag is determined 
                according to the length of key.
                
    :param compressed: (optional) if set to True private key corresponding compressed public key,
                       by default set to True. Recommended use only compressed public key.
    :param testnet: (optional) if set to True mean that this private key for testnet Bitcoin network.

    """
    def __init__(self, key, compressed=True, testnet=False):
        if isinstance(key, str):
            try:
                key = unhexlify(key)
            except:
                if is_wif_valid(key):
                    key = PrivateKey(key)

        if isinstance(key, bytes):
            if len(key) == 32:
                key = PrivateKey(key, compressed=compressed, testnet=testnet)
            elif is_public_key_valid(key):
                public_key = key
                self.testnet = testnet
                self.compressed = True if len(key) == 33 else False
            else:
                raise TypeError("key invalid")

        if isinstance(key, PrivateKey):
            #: flag for testnet network private key  (boolean)
            self.testnet = key.testnet
            #: flag for compressed type of corresponding public key (boolean)
            self.compressed = key.compressed
            public_key = private_to_public_key(key.key,
                                        compressed=key.compressed,
                                        hex=False)
        #: public key in  bytes (bytes)
        self.key = public_key
        #: public key in HEX (string)
        self.hex = hexlify(self.key).decode()

    def __str__(self):
        return self.hex


class Address():
    """
    The class for Address object.

    :param key: (optional) one of this types allowed:
    
                - private key WIF format
                - instance of ``PrivateKey``
                - private key HEX encoded string
                - instance of ``PublicKey``
                
                In case no key specified new Address will be created with random keys.
    :param address_type: (optional) P2PKH, PUBKEY, P2WPKH, P2SH_P2WPKH, by default P2WPKH.
    :param compressed: (optional) if set to True private key corresponding compressed public key,
                       by default set to True. Recommended use only compressed public key.
    :param testnet: (optional) if set to True mean that this private key for testnet Bitcoin network.

    In case instanse is created from WIF private key, ``PrivateKey`` or ``PublicKey`` compressed and testnet flags
    already contain in initial key parameter and will be ignored.
    """
    def __init__(self, key=None,
                 address_type="P2WPKH", testnet=False, compressed=True):
        if key is None:
            #: instance of ``PrivateKey`` class
            self.private_key = PrivateKey(testnet=testnet,
                                          compressed=compressed)
            #: instance of ``PublicKey`` class
            self.public_key = PublicKey(self.private_key)
            #: flag for testnet network address  (boolean)
            self.testnet = testnet
        if isinstance(key, str) or isinstance(key, bytes):
            key = PrivateKey(key, testnet=testnet, compressed=compressed)
        if isinstance(key, PrivateKey):
            self.private_key = key
            self.testnet = key.testnet
            compressed = key.compressed
            self.public_key = PublicKey(self.private_key)
        elif isinstance(key, PublicKey):
            self.public_key = key
            self.testnet = testnet
            compressed = key.compressed
        if address_type not in ("P2PKH", "PUBKEY", "P2WPKH", "P2SH_P2WPKH"):
            raise TypeError("address type invalid")
        if not compressed:
            if address_type not in ("P2PKH", "PUBKEY", "P2SH"):
                raise TypeError("compressed public key invalid")
        #: flag for testnet network address  (boolean)
        self.type = address_type

        if address_type in ("P2WPKH"):
            #: version of witness program for SEGWIT address (string)
            self.witness_version = 0
        else:
            self.witness_version = None
        self.compressed = compressed
        if address_type == "P2SH_P2WPKH":
            #: flag for script hash address (boolean)
            self.script_hash = True
            #: redeeem script, only for P2SH_P2WPKH (bytes)
            self.redeem_script = public_key_to_p2sh_p2wpkh_script(self.public_key.key)
            #: redeeem script HEX, only for P2SH_P2WPKH (string)
            self.redeem_script_hex = hexlify(self.redeem_script).decode()
            #: address hash
            self.hash = hash160(self.redeem_script)
            self.witness_version = None
        else:
            self.script_hash = False
            self.hash = hash160(self.public_key.key)
        #: address hash HEX (string)
        self.hash_hex = hexlify(self.hash).decode()
        #: address in base58 or bech32 encoding (string)
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
        if isinstance(script, str):
            script = unhexlify(script)
        self.script = script
        self.script_hex = hexlify(self.script).decode()
        self.hash = hash160(self.script)
        self.script_opcodes = decode_script(self.script)
        self.script_opcodes_asm = decode_script(self.script, 1)
        self.address = hash_to_address(self.hash,
                                       script_hash=True,
                                       witness_version=self.witness_version,
                                       testnet=self.testnet)

