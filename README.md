# pybtc
Python bitcoin library


### Basic Examples

#### Create private key

    >>> from pybtc import *
    >>> create_priv()
    b'\xc8\xf5tGf\x00+4\x1c\xe3\xb6\x00\xf4\x14w\x1d\xf0{jiY&4`v\xd4\tmv!\x0f\x1f'
    >>>
    >>> priv = create_priv()
    >>> priv
    b'_`\xd7@\x9e\xdb\xbbB5O%@\xd6\x92\xb1\x0e*\xcd\xb6\x89!\xa3JE\xb0\xb6:\x8c\x04\x88\xc9\xa5'
    >>>
    >>> priv2WIF(priv)  
    'KzR7Z5xNnSYqxKZriSrWk4nQFU2qPJUcD4AoD7ckhy1c68A4zvkW'
    >>>
    >>> priv2WIF(priv, compressed = False)  # Mainnet compressed WIF format
    '5JYHtgBjYbLT3ZkhGHHCivscdMdDKeVTZBgq5ZK51fyKpqKDhYv' # Mainnet uncompressed WIF format
    >>>
    >>> priv2WIF(priv, testnet = True)
    'cQn71zxEDWF77m386rfe7PHTshLF3kaJH6KGKY5GD5fcLsCqpPbg'
    >>>
    >>> priv2WIF(priv, compressed = True, testnet = True) # Testnet compressed WIF format
    'cQn71zxEDWF77m386rfe7PHTshLF3kaJH6KGKY5GD5fcLsCqpPbg'
    >>>
    >>> priv2WIF(priv, compressed = False, testnet = True) # Testnet uncompressed WIF format
    '92JvUR1H8pQb1dFytdB7bXRaH1yvUp2eu8YnABfaMQiNbuKiPVL'
    >>>
    >>> WIF2priv("KzR7Z5xNnSYqxKZriSrWk4nQFU2qPJUcD4AoD7ckhy1c68A4zvkW")
    b'_`\xd7@\x9e\xdb\xbbB5O%@\xd6\x92\xb1\x0e*\xcd\xb6\x89!\xa3JE\xb0\xb6:\x8c\x04\x88\xc9\xa5'
    >>>
    
#### Public key from private key

    >>> from pybtc import *
    >>> priv2pub("KzR7Z5xNnSYqxKZriSrWk4nQFU2qPJUcD4AoD7ckhy1c68A4zvkW")
    b'\x02\xb1-\xc2\x03u\xda\x00*7t\xb9c\xe4A\xdb\x1c\xe0\x89\xb8W\x13\x86\xbe\x82\xee(\x11nrj\xb06'
    >>>
    >>> priv2pub("KzR7Z5xNnSYqxKZriSrWk4nQFU2qPJUcD4AoD7ckhy1c68A4zvkW", hex = True)
    '02b12dc20375da002a3774b963e441db1ce089b8571386be82ee28116e726ab036'
    >>>
    >>> priv = WIF2priv("KzR7Z5xNnSYqxKZriSrWk4nQFU2qPJUcD4AoD7ckhy1c68A4zvkW")
    >>> priv
    b'_`\xd7@\x9e\xdb\xbbB5O%@\xd6\x92\xb1\x0e*\xcd\xb6\x89!\xa3JE\xb0\xb6:\x8c\x04\x88\xc9\xa5'
    >>>
    >>> priv2pub(priv, hex = True)
    '02b12dc20375da002a3774b963e441db1ce089b8571386be82ee28116e726ab036'
    >>>

#### Address from public key/private key

    >>> from pybtc import *
    >>> # address in bech32 format
    ...
    >>> pub2address(priv2pub("KzR7Z5xNnSYqxKZriSrWk4nQFU2qPJUcD4AoD7ckhy1c68A4zvkW"))
    'bc1q3hs6985qftzrvfl7aqcshsf7equapuuxzr2kcv'
    >>>
    >>> # address in legacy format
    ...
    >>> pub2address(priv2pub("KzR7Z5xNnSYqxKZriSrWk4nQFU2qPJUcD4AoD7ckhy1c68A4zvkW"), witness_version = None)
    '1DwCaTcMTT5kZmH4wCevDe5nyzffi2Bz9p'
    >>>
    >>> # uncompressed public key deprecated for bech32 segwit addresses fromat
    ...
    >>> pub2address(priv2pub("5JYHtgBjYbLT3ZkhGHHCivscdMdDKeVTZBgq5ZK51fyKpqKDhYv"))
    Traceback (most recent call last):
      File "<stdin>", line 1, in <module>
      File "/usr/local/lib/python3.6/site-packages/pybtc/tools.py", line 233, in pub2address
        assert len(pubkey) == 33
    AssertionError
    >>>
    >>> # uncompressed public key legacy format
    ...
    >>> pub2address(priv2pub("5JYHtgBjYbLT3ZkhGHHCivscdMdDKeVTZBgq5ZK51fyKpqKDhYv"), witness_version = None)
    '1EbTeoa1QgZaSHZFznrhNdKrRbbQupVwuZ'
    >>>
    >>> # testnet addresses
    ...
    >>> pub2address(priv2pub("KzR7Z5xNnSYqxKZriSrWk4nQFU2qPJUcD4AoD7ckhy1c68A4zvkW"), testnet = True)
    'tb1q3hs6985qftzrvfl7aqcshsf7equapuuxg939rl'
    >>>
    >>> pub2address(priv2pub("KzR7Z5xNnSYqxKZriSrWk4nQFU2qPJUcD4AoD7ckhy1c68A4zvkW"), witness_version = None, testnet = True)
    'mtT9sWhLGUX1LskgemdJ3ZJ7qzGNaygcXP'
    >>>

