import os

ROOT_DIR = os.path.abspath(os.path.dirname(__file__))
BIP0039_DIR = os.path.normpath(os.path.join(ROOT_DIR, 'bip39_word_list'))

MAX_AMOUNT = 2100000000000000
SIGHASH_ALL = 0x00000001
SIGHASH_NONE = 0x00000002
SIGHASH_SINGLE = 0x00000003
SIGHASH_ANYONECANPAY = 0x00000080
ECDSA_SEC256K1_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

MAINNET_ADDRESS_BYTE_PREFIX = b'\x00'
TESTNET_ADDRESS_BYTE_PREFIX = b'\x6f'
MAINNET_SCRIPT_ADDRESS_BYTE_PREFIX = b'\x05'
TESTNET_SCRIPT_ADDRESS_BYTE_PREFIX = b'\xc4'
MAINNET_SEGWIT_ADDRESS_BYTE_PREFIX = b'\x03\x03\x00\x02\x03'
TESTNET_SEGWIT_ADDRESS_BYTE_PREFIX = b'\x03\x03\x00\x14\x02'

MAINNET_ADDRESS_PREFIX = '1'
TESTNET_ADDRESS_PREFIX = 'm'
TESTNET_ADDRESS_PREFIX_2 = 'n'
MAINNET_SCRIPT_ADDRESS_PREFIX = '3'
TESTNET_SCRIPT_ADDRESS_PREFIX = '2'

MAINNET_PRIVATE_KEY_UNCOMPRESSED_PREFIX = '5'
MAINNET_PRIVATE_KEY_COMPRESSED_PREFIX = 'K'
MAINNET_PRIVATE_KEY_COMPRESSED_PREFIX_2 = 'L'
TESTNET_PRIVATE_KEY_UNCOMPRESSED_PREFIX = '9'
TESTNET_PRIVATE_KEY_COMPRESSED_PREFIX = 'c'

ADDRESS_PREFIX_LIST = (MAINNET_ADDRESS_PREFIX,
                       TESTNET_ADDRESS_PREFIX,
                       TESTNET_ADDRESS_PREFIX_2,
                       MAINNET_SCRIPT_ADDRESS_PREFIX,
                       TESTNET_SCRIPT_ADDRESS_PREFIX)

PRIVATE_KEY_PREFIX_LIST = (MAINNET_PRIVATE_KEY_UNCOMPRESSED_PREFIX,
                           MAINNET_PRIVATE_KEY_COMPRESSED_PREFIX,
                           MAINNET_PRIVATE_KEY_COMPRESSED_PREFIX_2,
                           TESTNET_PRIVATE_KEY_UNCOMPRESSED_PREFIX,
                           TESTNET_PRIVATE_KEY_COMPRESSED_PREFIX)

MAINNET_PRIVATE_KEY_BYTE_PREFIX = b'\x80'
TESTNET_PRIVATE_KEY_BYTE_PREFIX = b'\xef'

MAINNET_SEGWIT_ADDRESS_PREFIX = 'bc'
TESTNET_SEGWIT_ADDRESS_PREFIX = 'tb'


SCRIPT_TYPES = {"P2PKH":        0,
                "P2SH":         1,
                "PUBKEY":       2,
                "NULL_DATA":    3,
                "MULTISIG":     4,
                "P2WPKH":       5,
                "P2WSH":        6,
                "NON_STANDARD": 7,
                "NULL_DATA_NON_STANDARD": 8
                }

SCRIPT_N_TYPES = {0: "P2PKH",
                  1: "P2SH",
                  2: "PUBKEY",
                  3: "NULL_DATA",
                  4: "MULTISIG",
                  5: "P2WPKH",
                  6: "P2WSH",
                  7: "NON_STANDARD",
                  8: "NULL_DATA_NON_STANDARD"
                }

# CONSTANTS hierarchical deterministic wallets (HD Wallets)
# m/44'/0' P2PKH
MAINNET_XPRIVATE_KEY_PREFIX = b'\x04\x88\xAD\xE4'
MAINNET_XPUBLIC_KEY_PREFIX = b'\x04\x88\xB2\x1E'

# m/44'/1' P2PKH
TESTNET_XPRIVATE_KEY_PREFIX = b'\x04\x35\x83\x94'
TESTNET_XPUBLIC_KEY_PREFIX = b'\x04\x35\x87\xCF'

# m/44'/0' P2PKH
MAINNET_M44_XPRIVATE_KEY_PREFIX = b'\x04\x88\xAD\xE4'
MAINNET_M44_XPUBLIC_KEY_PREFIX = b'\x04\x88\xB2\x1E'

# m/44'/1' P2PKH
TESTNET_M44_XPRIVATE_KEY_PREFIX = b'\x04\x35\x83\x94'
TESTNET_M44_XPUBLIC_KEY_PREFIX = b'\x04\x35\x87\xCF'



# m/49'/0' P2WPKH in P2SH
MAINNET_M49_XPRIVATE_KEY_PREFIX = b'\x04\x9d\x78\x78'
MAINNET_M49_XPUBLIC_KEY_PREFIX = b'\x04\x9d\x7c\xb2'

# m/49'/1' P2WPKH in P2SH
TESTNET_M49_XPRIVATE_KEY_PREFIX = b'\x04\x4a\x4e\x28'
TESTNET_M49_XPUBLIC_KEY_PREFIX = b'\x04\x4a\x52\x62'

# m/84'/0' P2WPKH
MAINNET_M84_XPRIVATE_KEY_PREFIX = b'\x04\xb2\x43\x0c'
MAINNET_M84_XPUBLIC_KEY_PREFIX = b'\x04\xb2\x47\x46'

# m/84'/1' P2WPKH
TESTNET_M84_XPRIVATE_KEY_PREFIX = b'\x04\x5f\x18\xbc'
TESTNET_M84_XPUBLIC_KEY_PREFIX = b'\x04\x5f\x1c\xf6'



HARDENED_KEY = 0x80000000
FIRST_HARDENED_CHILD = 0x80000000
PATH_LEVEL_BIP0044 = [0x8000002C, 0x80000000, 0x80000000, 0, 0]
TESTNET_PATH_LEVEL_BIP0044 = [0x8000002C, 0x80000001, 0x80000000, 0, 0]

MINER_COINBASE_TAG = {
    b"BTC Guild": {"name": "BTC Guild", "link": ""},
    b"lubian.com": {"name": "Lubian.com", "link": "https://lubian.com/"},
    b"MiningCity": {"name": "MiningCity", "link": "https://www.miningcity.com/"},
    b"Buffett": {"name": "Buffett", "link": ""},
    b"binance": {"name": "Binance.com", "link": "https://binance.com/"},
    b"Binance": {"name": "Binance.com", "link": "https://binance.com/"},
    b"binance.com": {"name": "Binance.com", "link": "https://binance.com/"},
    b"bytepool.com": {"name": "Bytepool", "link": "https://bytepool.com/"},
    b"ukrpool.com": {"name": "Ukrpool", "link": "https://ukrpool.com/"},
    b"Ukrpool.com": {"name": "Ukrpool", "link": "https://ukrpool.com/"},
    b"SpiderPool": {"name": "SpiderPool", "link": "https://www.spiderpool.com/"},
    b"okex.com": {"name": "OKEX", "link": "https://www.okex.com/"},
    b"BitMinter": {"name": "BitMinter", "link": "https://bitminter.com/"},
    b"Eligius": {"name": "Eligius", "link": "http://eligius.st/"},
    b"ghash.io": {"name": "GHash.IO", "link": "https://ghash.io/"},
    b"mmpool": {"name": "mmpool", "link": "http://mmpool.org/pool"},
    b"KnCMiner": {"name": "KnCMiner", "link": "http://www.kncminer.com/"},
    b"F2Pool": {"name": "F2Pool", "link": "https://www.f2pool.com/"},
    "七彩神仙鱼".encode(): {"name": "F2Pool", "link": "https://www.f2pool.com/"},
    b'\xf0\x9f\x90\x9f': {"name": "F2Pool", "link": "https://www.f2pool.com/"},
    b"slush": {"name": "Slush", "link": "http://mining.bitcoin.cz/"},
    b"AntPool": {"name": "AntPool", "link": "https://www.antpool.com/"},
    b"Mined by AntPool": {"name": "AntPool", "link": "https://www.antpool.com/"},
    b"Kano": {"name": "Kano CK", "link": "https://kano.is/"},
    b"NiceHashSolo": {"name": "NiceHash Solo", "link": "https://solo.nicehash.com/"},
    b"BitClub Network": {"name": "BitClub", "link": "https://bitclubpool.com/"},
    b"BTCChina Pool": {"name": "BTCC", "link": "https://pool.btcc.com/"},
    b"btcchina.com": {"name": "BTCC", "link": "https://pool.btcc.com/"},
    b"BTCChina.com": {"name": "BTCC", "link": "https://pool.btcc.com/"},
    b"BTCC": {"name": "BTCC", "link": "https://pool.btcc.com/"},
    b"BW Pool": {"name": "BW.COM", "link": "https://bw.com/"},
    b"BitFury": {"name": "BitFury", "link": "http://bitfury.com/"},
    b"Bitfury": {"name": "BitFury", "link": "http://bitfury.com/"},
    b"pool34": {"name": "21 Inc.", "link": "https://21.co/"},
    b"Mined by 1hash.com": {"name": "1Hash", "link": "https://1hash.com/"},
    b"HaoBTC": {"name": "HaoBTC", "link": "https://haobtc.com/"},
    b"BCMonster": {"name": "BCMonster", "link": "http://bitcoin.co.pt/"},
    b"ViaBTC": {"name": "ViaBTC", "link": "http://www.viabtc.com/"},
    b"BTC.TOP": {"name": "BTC.TOP", "link": "http://btc.top"},
    b"DPOOL.TOP":  {"name": "DPOOL", "link": "https://www.dpool.top/"},
    b"Rawpool.com":   {"name": "Rawpool.com", "link": "https://www.rawpool.com/"},
    b"ckpool.org": {"name": "CKPool", "link": "http://ckpool.org"},
    b"ckpool": {"name": "CKPool", "link": "http://ckpool.org"},
    b"KanoPool": {"name": "KanoPool", "link": "https://kano.is/"},
    b"Huobi": {"name": "Huobi", "link": "https://www.poolhb.com"},
    b"HuoBi": {"name": "Huobi", "link": "https://www.poolhb.com"},
    b"58coin.com": {"name": "58coin", "link": "http://58coin.com"},
    b"1THash": {"name": "1THash", "link": "https://www.1thash.com/"},
    b"NovaBlock": {"name": "NovaBlock", "link": "https://novablock.com/"},
    b"pool.bitcoin.com": {"name": "Bitcoin.com", "link": "https://pool.bitcoin.com"},
    b"BTC.COM": {"name": "BTC.COM", "link": "http://btc.com/"},
    b"BTC.com": {"name": "BTC.com", "link": "http://btc.com/"},
    b"BTCcom": {"name": "BTC.com", "link": "http://btc.com/"},
    b"bpool": {"name": "BTC.com", "link": "http://btc.com/"},
    b"SBICrypto.com": {"name": "SBI Crypto", "link": "https://sbicrypto.com"},
    b"TMSPOOL": {"name": "TANMAS MINE", "link": "https://btc.tmspool.top"},
    b"one_more_mcd": {"name": "EMCD", "link": "https://pool.emcd.io"},
    b"Bitdeer": {"name": "Bitdeer", "link": "https://www.bitdeer.com"},
    b"gbminers": {"name": "gbminers", "link": "http://gbminers.com"},
    b"BATPOOL":  {"name": "batpool", "link": "https://www.batpool.com"},
    b"Bitcoin-India": {"name": "BitcoinIndia", "link": "https://pool.bitcoin-india.org"},
    b"Bixin": {"name" : "Bixin", "link" : "https://haopool.com"},
    b"CANOE": {"name": "CANOE", "link": "https://www.canoepool.com/"},
    b"ConnectBTC": {"name": "ConnectBTC", "link": "https://www.connectbtc.com"},
    b"poolin": {"name": "Poolin", "link": "https://www.poolin.com"},
    b"BW.com": {"name": "BW.com", "link": "https://bw.com"},
    b"bw.com": {"name": "BW.com", "link": "https://bw.com"},
    b"okkong": {"name": "OKKONG", "link": "https://hash.okkong.com"},
    b"Foundry USA": {"name": "Foundry USA", "link": "https://foundrydigital.com/"},
    b"SigmaPool": {"name": "SigmaPool", "link": "https://btc.sigmapool.com/"},
    b"sigmaPool": {"name": "SigmaPool", "link": "https://btc.sigmapool.com/"},
    b"sigmapool": {"name": "SigmaPool", "link": "https://btc.sigmapool.com/"},
    b"BTPOOL": {"name": "BTPool", "link": ""},
    b"Bitcoin-Russia.ru": {"name": "Bitcoin Russia", "link": "https://bitcoin-russia.ru/"},
    b"Kanpool.com": {"name": "Kanpool", "link": "http://kanpool.com"},
    b"tigerpool.net": {"name": "Tiger pool", "link": ""},
    b"LTC.TOP": {"name": "LTC.TOP", "link": ""},
    b"prohashing.com": {"name": "prohashing.com", "link": "https://prohashing.com"},
    b"GIVE-ME-COINS.com": {"name": "give-me-coins.com", "link": "http://give-me-coins.com"},
    b"XNPool": {"name": "XNPool", "link": "https://www.xnpool.cn"},
    b"Easy2Mine": {"name": "Easy2Mine", "link": "https://www.easy2mine.com"}
}

MINER_PAYOUT_TAG = { "1CK6KHY6MHgYvmRQ4PAafKYDrg1ejbH1cE" : {"name" : "Slush", "link" : "https://slushpool.com"},
                     "1Bf9sZvBHPFGVPX71WX2njhd1NXKv5y7v5" : {"name": "BTC.COM", "link": "http://btc.com"},
                     "1AqTMY7kmHZxBuLUR5wJjPFUvqGs23sesr" : {"name" : "Slush", "link" : "https://slushpool.com"},
                     "1AcAj9p6zJn4xLXdvmdiuPCtY7YkBPTAJo" : {"name" : "BitFury", "link" : "http://bitfury.com"},
                     "3HuobiNg2wHjdPU2mQczL9on8WF7hZmaGd" : {"name" : "Huobi", "link" : "http://www.huobi.com"},
                     "1JLRXD8rjRgQtTS9MvfQALfHgGWau9L9ky" : {"name" : "BW.COM", "link" : "https://www.bw.com"},
                     "155fzsEBHy9Ri2bMQ8uuuR3tv1YzcDywd4" : {"name" : "BitClub", "link" : "https://bitclubpool.com"},
                     "14yfxkcpHnju97pecpM7fjuTkVdtbkcfE6" : {"name" : "BitFury", "link" : "http://bitfury.com"},
                     "15rQXUSBQRubShPpiJfDLxmwS8ze2RUm4z" : {"name" : "21 Inc.", "link" : "https://21.co"},
                     "1CdJi2xRTXJF6CEJqNHYyQDNEcM3X7fUhD" : {"name" : "21 Inc.", "link" : "https://21.co"},
                     "1GC6HxDvnchDdb5cGkFXsJMZBFRsKAXfwi" : {"name" : "21 Inc.", "link" : "https://21.co"},
                     "1F1xcRt8H8Wa623KqmkEontwAAVqDSAWCV" : {"name" : "1Hash", "link" : "http://www.1hash.com"},
                     "1P4B6rx1js8TaEDXvZvtrkiEb9XrJgMQ19" : {"name" : "Telco 214","link" : "http://www.telco214.com"},
                     "1MoYfV4U61wqTPTHCyedzFmvf2o3uys2Ua" : {"name" : "Telco 214","link" : "http://www.telco214.com"},
                     "1GaKSh2t396nfSg5Ku2J3Yn1vfVsXrGuH5" : {"name" : "Telco 214","link" : "http://www.telco214.com"},
                     "1AsEJU4ht5wR7BzV6xsNQpwi5qRx4qH1ac" : {"name" : "Telco 214","link" : "http://www.telco214.com"},
                     "1DXRoTT67mCbhdHHL1it4J1xsSZHHnFxYR" : {"name" : "Telco 214","link" : "http://www.telco214.com"},
                     "1CNq2FAw6S5JfBiDkjkYJUVNQwjoeY4Zfi" : {"name" : "Telco 214","link" : "http://www.telco214.com"},
                     "152f1muMCNa7goXYhYAQC61hxEgGacmncB" : {"name" : "BTCC", "link" : "https://pool.btcc.com"},
                     "3KJrsjfg1dD6CrsTeHdHVH3KqMpvL2XWQn" : {"name" : "Poolin", "link" : "https://www.poolin.com"},
                     "13hQVEstgo4iPQZv9C7VELnLWF7UWtF4Q3" : {"name" : "Bixin", "link" : "https://haopool.com/"},
                     "1GP8eWArgpwRum76saJS4cZKCHWJHs9PQo" : {"name": "CANOE", "link": "https://www.canoepool.com/"}}



LN2SQUARED = 0.4804530139182014246671025263266649717305529515945455
LN2 = 0.6931471805599453094172321214581765680755001343602552
