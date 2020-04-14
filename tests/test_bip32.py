import pytest

from pybtc.functions.encode import decode_base58
from pybtc.functions.encode import encode_base58
from pybtc.functions.bip32 import xprivate_to_xpublic_key
from pybtc.functions.bip32 import create_master_xprivate_key
from pybtc.functions.bip39_mnemonic import mnemonic_to_seed
from pybtc.functions.bip39_mnemonic import entropy_to_mnemonic
from pybtc.functions.bip32 import decode_path
from pybtc.functions.bip32 import derive_xkey
from pybtc.functions.bip32 import derive_child_xprivate_key
from pybtc.functions.bip32 import derive_child_xpublic_key


def test_create_master_xprivate_key():
    e = "6afd4fd96ca02d0b7038429b77e8b32042fc205d031144054086130e8d83d981"
    xp = "xprv9s21ZrQH143K4LAkSUTJ3JiZ4cJc1FyRxCbPoWTQVssiezx3gpav8iJdHgg" \
         "BTTUv37iQUrfNDYpGmTSP6zwFD2kJAFiUzpewivZUD6Jqdai"
    assert xp == create_master_xprivate_key(mnemonic_to_seed(entropy_to_mnemonic(e)))
    assert decode_base58(xp,
                         checksum=True) == create_master_xprivate_key(mnemonic_to_seed(entropy_to_mnemonic(e)),
                                                           base58=False)

def test_xprivate_to_xpublic_key():
    m = "debate pattern hotel silly grit must bronze athlete kitten salute salmon cat control hungry little"
    seed = mnemonic_to_seed(m)
    xPriv = create_master_xprivate_key(seed, hex=True)
    xp = "xpub661MyMwAqRbcFRtq6C9uK3bk7pmqc5ahhqDjxx6dfge6njx6jU9EhFwpLf" \
         "iE6tQv8gjuez5PkQfxTZw4UUwwkut34JRYLWpJLNGPcUCGxj8"
    assert xp == xprivate_to_xpublic_key(xPriv)
    xPriv = create_master_xprivate_key(seed)
    assert xp == xprivate_to_xpublic_key(xPriv)
    xp = "xpub661iyMwAqRbcFRtq6C9uK3bk7pmqc5ahhqDjxx6dfge6njx6jU9EhFwpLf" \
         "iE6tQv8gjuez5PkQfxTZw4UUwwkut34JRYLWpJLNGPcUCGxj8"
    with pytest.raises(ValueError):
        xprivate_to_xpublic_key(xp)
    with pytest.raises(TypeError):
        xprivate_to_xpublic_key(5656)

    p = "0488adez000000000000000000591dc86e17ddeda60b0bcbd4ada7ded84009c979d7a6c90e19106a51420b08d900a5" \
        "595efba1a78dade67a53672ae52f2855e513b1bbc7381195e77ce6800da7f0"
    with pytest.raises(ValueError):
        xprivate_to_xpublic_key(p)
    xPriv = "tprv8ZgxMBicQKsPf9QH73JoCxLYNjipEn1SHkWWfvsryrNCSbh8gBvfeTg5Crq" \
            "qTpsEQZFBUxH8NuQ5EJz8EDHC261tgtvnfBNze2Jteoxhi47"
    assert "tpubD6NzVbkrYhZ4YcS4zgyPcMzewmEkQ7CLs47HxSvAQ8AbH5wuJakFpxHwNyXD" \
           "SmSDzNQmkKx2unk3xTDNN716cAKbgr6CyPm3hsAW4CqPVK2" == xprivate_to_xpublic_key(xPriv)

    assert decode_base58("tpubD6NzVbkrYhZ4YcS4zgyPcMzewmEkQ7CLs47HxSvAQ8AbH5wuJakFpxHwNyXD" \
                         "SmSDzNQmkKx2unk3xTDNN716cAKbgr6CyPm3hsAW4CqPVK2",
                         checksum=True).hex() == xprivate_to_xpublic_key(xPriv, hex=True)

    assert decode_base58("tpubD6NzVbkrYhZ4YcS4zgyPcMzewmEkQ7CLs47HxSvAQ8AbH5wuJakFpxHwNyXD" \
                         "SmSDzNQmkKx2unk3xTDNN716cAKbgr6CyPm3hsAW4CqPVK2",
                         checksum=True) == xprivate_to_xpublic_key(xPriv, base58=False, hex=False)

def test_decode_path():
    assert decode_path("m/44'/0'/0'") == [ 2147483692, 2147483648, 2147483648 ]
    assert decode_path("m/44'/0'/1'") == [ 2147483692, 2147483648, 2147483649 ]
    assert decode_path("m/0/3/4") == [ 0, 3, 4 ]
    with pytest.raises(Exception):
        decode_path("0/0/3/4")
    assert decode_path("0", True) == [0]

def test_derive_xkey():
    root = "xprv9s21ZrQH143K39fFeGf2cWBTZ6NVj6ZsQ7nEK9f5pWqt4YwHPhnC" \
           "F3GtMsPNA9cCz1j8j9Zs493ejkzJqUWqwGqQ2J8iNc1jFtFPbie7bZ4"
    assert derive_xkey(root, "m/0") == "xprv9v7aNJTyjf9pZ2e1XwaKwTaiYqmwy9C43GPrczk9NauP4aWYqeKh" \
                                       "5UfE3ocfV92UGFKBbQNZib8TDtqD8y5axYQMUzVJzHXphdNF6Cc6YM3"
    assert derive_xkey(root, decode_path("m/0")) == "xprv9v7aNJTyjf9pZ2e1XwaKwTaiYqmwy9C43GPrczk9NauP4aWYqeKh" \
                                                    "5UfE3ocfV92UGFKBbQNZib8TDtqD8y5axYQMUzVJzHXphdNF6Cc6YM3"
    assert derive_xkey(root, "m/0'") == "xprv9v7aNJU85KgnkrGKiEJMTnZJMSpbAvQdcUGm2q4s7Z2ZPA9iTwNd" \
                                       "D92ESDXbxLt6WAsjaT5xHQNNgHBmwjgwscmPjE1dDuQ5rVC9Jowgu8q"
    assert derive_xkey(root, "m/1") == "xprv9v7aNJTyjf9pazc9j5X7CkK3t4ywxLzsWazZL9x8JE1f8f7dsv6" \
                                        "xjtWEZN2cahUYqaEkr27oyGfc7Y8KG18B55j7h57W3SdiAvXcztzB7MV"
    assert derive_xkey(root, "m/44'/0'/0'") == "xprv9zAN5JC2upM319x3bsP9aa1jbE9MoyXNuSkm9rTggLBgUSHwsvigCr" \
                                               "wb3VJHpkb5KLteb9jwCpXnk7kS5ac3Av8Vn5UG2PgTdrxb9wPeipW"
    assert derive_xkey(root, "m/44'/0'/1'") == "xprv9zAN5JC2upM355bhe2xJWyzEVg7SD15PxVkN6FWPTjFPAkKoNoxPm" \
                                               "xvC76SK6k7HDc1WQhYaXYyEUTTuVLYbKomAna5pFbDJCMVzfKHfZUS"
    pub = "xpub6D9iUoivkBuLHZgAk4VJt7vy3hwvcToFKifxtdv124nN3YewvMGeKmE" \
          "fxLVZFLTCzQLS9NBwUzFVi66w5YnHM5o3y9GwQJSfroev539tkUZ"
    assert derive_xkey(pub, "m/0") == "xpub6FPUvcox6BxqQCt2GRHTdy5ehEKr3JRX1DjZTUutrRh8VsWNS6tfNZd5ZctuDZhm5d" \
                                      "RdepkwBgz77p8dVmNuMbBifts556S6jy3gERc3Tfy"
    assert derive_xkey(pub, "m/0/3/4") == "xpub6J7BeAMm9AYT56iBvZ8ceMksXimevjhcV9yCWM7UdkFZXWDvNHb7qLkFwwewtZp" \
                                          "8bVKhsqZfHfvZN6KpT59BuQy4e93pP3AoXk8uzCu8aPJ"

def test_derive_child_xprivate_key():
    xpriv = "xprv9s21ZrQH143K3CSC8gBJRWPHPzi8Y17VzhuMGgSyyiGYzbbCnmUE1zpR2iQCz" \
            "VGPGAQBy2m7LTEtPAvfB6p2ECoQBAWtQYgYHpn1UFQv6Mi"
    assert "xprv9uxHkb3zFYjmC9AshDxocSv8SWphDkWq7VpNauF8hhGNMuqK2o4AKhhhuFADy1H5pVVAdZJCnyDmjZBZm" \
           "gUR8aciXXELWfU6tCF4BCrhz5m" == \
           encode_base58(derive_child_xprivate_key(decode_base58(xpriv, checksum=True), 1), checksum=True)


    assert "xprv9uxHkb3zFYjm9WnMk636CLyiCt2h6mgVR2u5iy8PgAkPW1xYCuUGYUzU6A4HWS7hDhKVQufiymoj9oYjqg" \
           "1h7331YjwVTfSBN97gSo65DiV"  == \
           encode_base58(derive_child_xprivate_key(decode_base58(xpriv, checksum=True), 0), checksum=True)

    assert "xprv9uxHkb3zFYzv3TK97XAQ5YykGBuFgMo5mKzjvQKuzbPf3FBeVgTC2ozTtspLBU2X4HWWFDocpB1sHjSX" \
           "Jby89m6cKhLhWUdhUWdF4o39kw4"  == \
           encode_base58(derive_child_xprivate_key(decode_base58(xpriv, checksum=True), 20000), checksum=True)

    assert "xprv9uxHkb3zFzs4rMGo9d25NcHCyePGswYHY6fMk76DzbZ5iCucy7VtdjYa1o4n28bnnGLW4ComhMjNiUKx" \
           "bgq6p6vc9zwHfHb1fvdhAvsURty" == \
           encode_base58(derive_child_xprivate_key(decode_base58(xpriv, checksum=True), 2000000), checksum=True)

def test_derive_child_xpublic_key():
    xpub = "xpub661MyMwAqRbcFgWfEhiJneL1x2YcwTqMMvpx54rbY3oXsPvMLJnUZo8tsxpGFsUrFW" \
            "9zMFKAGzaDDy1pR2uoohh1CW24Se1vkSnXRMqPV9R"
    assert "xpub68weA6at5vJ4Mzrpr7a6ZUvSkusBWEQLnFpgXMY1EWHNNpHgkSnX6HJwwSjN7z" \
           "9PFrgTLK6gtWZ37o3b2ZAQSc4V9GdxdjVTjymSVit5Sai"  == \
           encode_base58(derive_child_xpublic_key(decode_base58(xpub, checksum=True), 0), checksum=True)


    assert "xpub68weA6at5vJ5fuUhS2bUgtse4cswz9VpU3UJAY93oUwpP8P4oDhTtGKizXsosJH99RWnnyD9txQ" \
           "XBAcyAEiykRDAoyHLCcpW2vkrnsSymDQ"   == \
           encode_base58(derive_child_xpublic_key(decode_base58(xpub, checksum=True), 30), checksum=True)

