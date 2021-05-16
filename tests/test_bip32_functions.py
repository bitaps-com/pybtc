import pytest

from pybtc.functions.encode import decode_base58
from pybtc.functions.encode import encode_base58
from pybtc.functions.key import wif_to_private_key
from pybtc.functions.bip32 import xprivate_to_xpublic_key
from pybtc.functions.bip32 import public_from_xpublic_key
from pybtc.functions.bip32 import private_from_xprivate_key
from pybtc.functions.bip32 import create_master_xprivate_key
from pybtc.functions.bip32 import is_xprivate_key_valid
from pybtc.functions.bip32 import is_xpublic_key_valid
from pybtc.functions.bip32 import path_xkey_to_bip32_xkey
from pybtc.functions.bip32 import bip32_xkey_to_path_xkey
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
    assert decode_path("0/0", True) == [0]

def test_derive_xkey():
    root = "xprv9s21ZrQH143K39fFeGf2cWBTZ6NVj6ZsQ7nEK9f5pWqt4YwHPhnC" \
           "F3GtMsPNA9cCz1j8j9Zs493ejkzJqUWqwGqQ2J8iNc1jFtFPbie7bZ4"
    assert derive_xkey(decode_base58(root, checksum=True), "m/0") == "xprv9v7aNJTyjf9pZ2e1XwaKwTaiYqmwy9C43GPrczk9NauP4aWYqeKh" \
                                       "5UfE3ocfV92UGFKBbQNZib8TDtqD8y5axYQMUzVJzHXphdNF6Cc6YM3"
    assert derive_xkey(root, decode_path("m/0")) == "xprv9v7aNJTyjf9pZ2e1XwaKwTaiYqmwy9C43GPrczk9NauP4aWYqeKh" \
                                                    "5UfE3ocfV92UGFKBbQNZib8TDtqD8y5axYQMUzVJzHXphdNF6Cc6YM3"
    assert derive_xkey(root, "m/0'") == "xprv9v7aNJU85KgnkrGKiEJMTnZJMSpbAvQdcUGm2q4s7Z2ZPA9iTwNd" \
                                       "D92ESDXbxLt6WAsjaT5xHQNNgHBmwjgwscmPjE1dDuQ5rVC9Jowgu8q"
    assert derive_xkey(root, "m/1") == "xprv9v7aNJTyjf9pazc9j5X7CkK3t4ywxLzsWazZL9x8JE1f8f7dsv6" \
                                        "xjtWEZN2cahUYqaEkr27oyGfc7Y8KG18B55j7h57W3SdiAvXcztzB7MV"
    assert derive_xkey(root, "m/44'/0'/0'", base58=True) == "xprv9zAN5JC2upM319x3bsP9aa1jbE9MoyXNuSkm9rTggLBgUSHwsvigCr" \
                                               "wb3VJHpkb5KLteb9jwCpXnk7kS5ac3Av8Vn5UG2PgTdrxb9wPeipW"
    assert derive_xkey(root, "m/44'/0'/1'") == "xprv9zAN5JC2upM355bhe2xJWyzEVg7SD15PxVkN6FWPTjFPAkKoNoxPm" \
                                               "xvC76SK6k7HDc1WQhYaXYyEUTTuVLYbKomAna5pFbDJCMVzfKHfZUS"
    pub = "xpub6D9iUoivkBuLHZgAk4VJt7vy3hwvcToFKifxtdv124nN3YewvMGeKmE" \
          "fxLVZFLTCzQLS9NBwUzFVi66w5YnHM5o3y9GwQJSfroev539tkUZ"
    assert derive_xkey(pub, "m/0", hex=True) == decode_base58("xpub6FPUvcox6BxqQCt2GRHTdy5ehEKr3JRX1DjZTUutrRh8VsWNS6tfNZd5ZctuDZhm5d" \
                                      "RdepkwBgz77p8dVmNuMbBifts556S6jy3gERc3Tfy", checksum= True).hex()
    assert derive_xkey(pub, "m/0", hex=False) == decode_base58("xpub6FPUvcox6BxqQCt2GRHTdy5ehEKr3JRX1DjZTUutrRh8VsWNS6tfNZd5ZctuDZhm5d" \
                                      "RdepkwBgz77p8dVmNuMbBifts556S6jy3gERc3Tfy", checksum= True)
    assert derive_xkey(pub, "m/0/3/4") == "xpub6J7BeAMm9AYT56iBvZ8ceMksXimevjhcV9yCWM7UdkFZXWDvNHb7qLkFwwewtZp" \
                                          "8bVKhsqZfHfvZN6KpT59BuQy4e93pP3AoXk8uzCu8aPJ"
    with pytest.raises(ValueError):
        derive_xkey("xprq9s21ZrQH143K39fFeGf2cWBTZ6NVj6ZsQ7nEK9f5pWqt4YwHPhnC" \
                    "F3GtMsPNA9cCz1j8j9Zs493ejkzJqUWqwGqQ2J8iNc1jFtFPbie7bZ4", "m/0'")


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

    with pytest.raises(ValueError):
        derive_child_xpublic_key(decode_base58(xpub, checksum=True), 30|0x80000000)

def test_public_from_xpublic_key():
    pub = "xpub6BP3EN8n7YTGYKL7nK9yUekCr9ixHK3taG2ATSkE5XjM7K12YMigC9pqUhj" \
          "2K2f4TRg8xvDfqpHsWsjBHoMdJ6QF9dfSeKALRiTFAi9dA5T"
    assert public_from_xpublic_key(pub) == \
           "02832b4cd1990dc9ffb7624bdc33e19061836f237f5ccd8730777a10bfca88944c"

    assert public_from_xpublic_key(decode_base58(pub, checksum=True))== \
           "02832b4cd1990dc9ffb7624bdc33e19061836f237f5ccd8730777a10bfca88944c"

    assert public_from_xpublic_key(decode_base58(pub, checksum=True).hex())== \
           "02832b4cd1990dc9ffb7624bdc33e19061836f237f5ccd8730777a10bfca88944c"
    with pytest.raises(TypeError):
        public_from_xpublic_key(423432)
    pub = "xpus6BP3EN8n7YTGYKL7nK9yUekCr9ixHK3taG2ATSkE5XjM7K12YMigC9pqUhj" \
          "2K2f4TRg8xvDfqpHsWsjBHoMdJ6QF9dfSeKALRiTFAi9dA5T"
    with pytest.raises(ValueError):
        public_from_xpublic_key(pub)

def test_private_from_xprivate_key():
    priv = "xprv9xPgprbtHAtyKqFegHcy7WoUJ7tTsrL3D36Zf4LcXCCNEWfszpQReMWMdSpjE9qo" \
          "sHonUirqo418nd6vG46yi34nbHQ8wvWjLLjzMBFKNqM"
    assert private_from_xprivate_key(priv) == \
           "L2BfXTBFwabUYoGkXKeR34f3TBpcThLtnC8yf6ZURvM952x8sWmz"

    assert private_from_xprivate_key(decode_base58(priv, checksum=True))== \
           "L2BfXTBFwabUYoGkXKeR34f3TBpcThLtnC8yf6ZURvM952x8sWmz"

    assert private_from_xprivate_key(decode_base58(priv, checksum=True).hex(), hex=True)== \
           wif_to_private_key("L2BfXTBFwabUYoGkXKeR34f3TBpcThLtnC8yf6ZURvM952x8sWmz", hex=True)
    assert private_from_xprivate_key(decode_base58(priv, checksum=True).hex(), wif=False)== \
           wif_to_private_key("L2BfXTBFwabUYoGkXKeR34f3TBpcThLtnC8yf6ZURvM952x8sWmz", hex=False)
    with pytest.raises(TypeError):
        private_from_xprivate_key(423432)
    pub = "xpus6BP3EN8n7YTGYKL7nK9yUekCr9ixHK3taG2ATSkE5XjM7K12YMigC9pqUhj" \
          "2K2f4TRg8xvDfqpHsWsjBHoMdJ6QF9dfSeKALRiTFAi9dA5T"
    with pytest.raises(ValueError):
        private_from_xprivate_key(pub)

    priv = "tprv8ZgxMBicQKsPf9QH73JoCxLYNjipEn1SHkWWfvsryrNCSbh8gBvfeTg5Crqq" \
           "TpsEQZFBUxH8NuQ5EJz8EDHC261tgtvnfBNze2Jteoxhi47"
    assert private_from_xprivate_key(priv) == \
           "cNu63US2f9jLLwDeD9321q1S5xviXCxSyem2GkFJjcF8DTWxqteC"

def test_is_xprivate_key_valid():
    assert is_xprivate_key_valid(decode_base58("xprv9xPgprbtHAtyKqFegHcy7WoUJ7tTsrL3D36Zf4LcXCCNEWfszpQR"
                                               "eMWMdSpjE9qosHonUirqo418nd6vG46yi34nbHQ8wvWjLLjzMBFKNqM",
                                               checksum=True)) == True
    assert is_xprivate_key_valid("tprv8ZgxMBicQKsPf9QH73JoCxLYNjipEn1SHkWWfvsryrNCSbh8gBv"
                                 "feTg5CrqqTpsEQZFBUxH8NuQ5EJz8EDHC261tgtvnfBNze2Jteoxhi47") == True
    assert is_xprivate_key_valid("yprvAJXHiBz6oBHZouVo25rgayS7ss1FGAkAsPMrtpTX7DrAHqocTrus"
                                 "QmMNuA2VoJyxJ9jsfAQFRFoRrDFKAhNoVgvhLYSZ5LWqQJy7fYUzRW8") == True
    assert is_xprivate_key_valid("uprv8tXDerPXZ1QsWSbPwQ6RR3S3YhsGBPzwCs2jTKmkMrk5VhWMvr6"
                                 "EGXLDE4oRTjX9pCMzERsgqZkd7bbgwuhCpKhVZEdDF6CUukNY3RLytkD") == True
    assert is_xprivate_key_valid("zprvAc4DSBwiaXyw2RdtM1CDXgzUe4BMm6K33G91Dr8PHCx8LiJLW8jY"
                                 "tUpdfrjuDy9ega3Pyg3xiNiEZCL3hSw1JWRzKxnz7k9hsnsH8R1Ckwk") == True
    assert is_xprivate_key_valid("vprv9DMUxX4ShgxMMjnWmkt3d8XYig1i81zS7yYxEifdjs7xYoKbBWF"
                                 "ntazMFGm1TeB5DqUnyuUFJE7AztDFfc7DcZP6RaKdq11yBUSBRvwZLXe") == True
    assert is_xprivate_key_valid("qprv9DMUxX4ShgxMMjnWmkt3d8XYig1i81zS7yYxEifdjs7xYoKbBWFn"
                                 "tazMFGm1TeB5DqUnyuUFJE7AztDFfc7DcZP6RaKdq11yBUSBRvwZLXe") == False
    assert is_xprivate_key_valid("") == False
    assert is_xprivate_key_valid("1212qsdbfnn,i;p/") == False

def test_is_xpublic_key_valid():
    assert is_xpublic_key_valid(decode_base58("xpub68isDcaF29MCeYMdJ6ZypmjogsM6bgx3ssCZyRyT4JYqPZcSkEQtK"
                                              "x6ag1FHnirP8tz9VNAn7cuJhBKf63ijyw1FPg2Po36TcuX725Mom1X",
                                              checksum=True)) == True
    assert is_xpublic_key_valid("tpubD6NzVbkrYhZ4YcS4zgyPcMzewmEkQ7CLs47HxSvAQ8AbH5wuJakF"
                                "pxHwNyXDSmSDzNQmkKx2unk3xTDNN716cAKbgr6CyPm3hsAW4CqPVK2") == True
    assert is_xpublic_key_valid("ypub6TZ8XHFAAptgVqYk8TMc2rqJrqVYYJwYnyinkpsLSJviSfRfzta"
                                "Sx1kihDCsndWJYY6xEqmLaHFraTwDok8knAgrG1ipNwuwtdakQibcvzB") == True
    assert is_xpublic_key_valid("upub57Wa4MvRPNyAivfs3RdRnBNn6jhkarina5xLFiBMvCH4NVqWUPQU"
                                "pKeh5KZfvYXDyYXStKeUzhrMcQt4p9upL1pW2EFdY8eMJjPA8UKuxaL") == True
    assert is_xpublic_key_valid("zpub6nPPpwv5KWSAM8jrxp9EEwvp2odzUvw3i6F1YDmDpKJbVmEuFYk"
                                "1a5QriRATnYADxBDkzKMu2wcQTkYnXSYmaQNT8MRExrjSAMePoDv2d2R") == True
    assert is_xpublic_key_valid("vpub5SLqN2bLY4WeaDrysnR3zGUHGhrCXUiHVCUZ375FJCewRbejj3a3"
                                "SPJq6XXFvTB9PBeFdoF3TNCuVhVdXrKq8FW6tZx483TqaTSoWx3U88j") == True
    assert is_xpublic_key_valid(decode_base58("vpuc5SLqN2bLY4WeaDrysnR3zGUHGhrCXUiHVCUZ375FJCewRbejj3a3"
                                              "SPJq6XXFvTB9PBeFdoF3TNCuVhVdXrKq8FW6tZx483TqaTSoWx3U88j",
                                              checksum=True)) == False
    assert is_xpublic_key_valid("qpub5SLqN2bLY4WeaDrysnR3zGUHGhrCXUiHVCUZ375FJCewRbejj3a3SPJq6XXFvTB9PBeFdoF3TNCuVhVdXrKq8FW6tZx483TqaTSoWx3U88j"
                                ) == False
    assert is_xpublic_key_valid("") == False
    assert is_xpublic_key_valid("1212qsdbfnn,i;p/") == False

def test_path_xkey_to_bip32_xkey():
    assert path_xkey_to_bip32_xkey(decode_base58("xpub68isDcaF29MCeYMdJ6ZypmjogsM6bgx3ssCZyRyT4JYqPZcS"
                                   "kEQtKx6ag1FHnirP8tz9VNAn7cuJhBKf63ijyw1FPg2Po36TcuX725Mom1X",
                                                 checksum=True)) == \
                                   "xpub68isDcaF29MCeYMdJ6ZypmjogsM6bgx3ssCZyRyT4JYqPZcSkE" \
                                   "QtKx6ag1FHnirP8tz9VNAn7cuJhBKf63ijyw1FPg2Po36TcuX725Mom1X"
    assert path_xkey_to_bip32_xkey(decode_base58("xpub68isDcaF29MCeYMdJ6ZypmjogsM6bgx3ssCZyRyT4JYqPZcS"
                                   "kEQtKx6ag1FHnirP8tz9VNAn7cuJhBKf63ijyw1FPg2Po36TcuX725Mom1X",
                                                 checksum=True).hex()) == \
                                   "xpub68isDcaF29MCeYMdJ6ZypmjogsM6bgx3ssCZyRyT4JYqPZcSkE" \
                                   "QtKx6ag1FHnirP8tz9VNAn7cuJhBKf63ijyw1FPg2Po36TcuX725Mom1X"

    with pytest.raises(ValueError):
        path_xkey_to_bip32_xkey("oeirfhoiwjefoiwe223")

    with pytest.raises(ValueError):
        path_xkey_to_bip32_xkey(decode_base58("xpuw68isDcaF29MCeYMdJ6ZypmjogsM6bgx3ssCZyRyT4JYqPZcS"
                                              "kEQtKx6ag1FHnirP8tz9VNAn7cuJhBKf63ijyw1FPg2Po36TcuX725Mom1X",
                                              checksum=True).hex())

    assert path_xkey_to_bip32_xkey("tpubD6NzVbkrYhZ4YcS4zgyPcMzewmEkQ7CLs47HxSvAQ8AbH5wuJa"
                                   "kFpxHwNyXDSmSDzNQmkKx2unk3xTDNN716cAKbgr6CyPm3hsAW4CqPVK2") == \
                                   "tpubD6NzVbkrYhZ4YcS4zgyPcMzewmEkQ7CLs47HxSvAQ8AbH5wuJakFp" \
                                   "xHwNyXDSmSDzNQmkKx2unk3xTDNN716cAKbgr6CyPm3hsAW4CqPVK2"

    assert path_xkey_to_bip32_xkey("ypub6TZ8XHFAAptgVqYk8TMc2rqJrqVYYJwYnyinkpsLSJviSfRfztaS"
                                   "x1kihDCsndWJYY6xEqmLaHFraTwDok8knAgrG1ipNwuwtdakQibcvzB") == \
                                   "xpub68isDcaF29MCeYMdJ6ZypmjogsM6bgx3ssCZyRyT4JYqPZcSkEQt" \
                                   "Kx6ag1FHnirP8tz9VNAn7cuJhBKf63ijyw1FPg2Po36TcuX725Mom1X"

    assert path_xkey_to_bip32_xkey("upub57Wa4MvRPNyAivfs3RdRnBNn6jhkarina5xLFiBMvCH4NVqWUPQU"
                                   "pKeh5KZfvYXDyYXStKeUzhrMcQt4p9upL1pW2EFdY8eMJjPA8UKuxaL") == \
                                   "tpubD6NzVbkrYhZ4YcS4zgyPcMzewmEkQ7CLs47HxSvAQ8AbH5wuJakF" \
                                   "pxHwNyXDSmSDzNQmkKx2unk3xTDNN716cAKbgr6CyPm3hsAW4CqPVK2"

    assert path_xkey_to_bip32_xkey("zpub6nPPpwv5KWSAM8jrxp9EEwvp2odzUvw3i6F1YDmDpKJbVmEuFYk1"
                                   "a5QriRATnYADxBDkzKMu2wcQTkYnXSYmaQNT8MRExrjSAMePoDv2d2R") == \
                                   "xpub68isDcaF29MCeYMdJ6ZypmjogsM6bgx3ssCZyRyT4JYqPZcSkEQt" \
                                   "Kx6ag1FHnirP8tz9VNAn7cuJhBKf63ijyw1FPg2Po36TcuX725Mom1X"

    assert path_xkey_to_bip32_xkey("vpub5SLqN2bLY4WeaDrysnR3zGUHGhrCXUiHVCUZ375FJCewRbejj3a3"
                                   "SPJq6XXFvTB9PBeFdoF3TNCuVhVdXrKq8FW6tZx483TqaTSoWx3U88j") == \
                                   "tpubD6NzVbkrYhZ4YcS4zgyPcMzewmEkQ7CLs47HxSvAQ8AbH5wuJakF" \
                                   "pxHwNyXDSmSDzNQmkKx2unk3xTDNN716cAKbgr6CyPm3hsAW4CqPVK2"

    assert path_xkey_to_bip32_xkey("xprv9xPgprbtHAtyKqFegHcy7WoUJ7tTsrL3D36Zf4LcXCCNEWfszpQR"
                                   "eMWMdSpjE9qosHonUirqo418nd6vG46yi34nbHQ8wvWjLLjzMBFKNqM") == \
                                   "xprv9xPgprbtHAtyKqFegHcy7WoUJ7tTsrL3D36Zf4LcXCCNEWfszpQR" \
                                   "eMWMdSpjE9qosHonUirqo418nd6vG46yi34nbHQ8wvWjLLjzMBFKNqM"

    assert path_xkey_to_bip32_xkey("tprv8ZgxMBicQKsPf9QH73JoCxLYNjipEn1SHkWWfvsryrNCSbh8gBvf"
                                   "eTg5CrqqTpsEQZFBUxH8NuQ5EJz8EDHC261tgtvnfBNze2Jteoxhi47") == \
                                   "tprv8ZgxMBicQKsPf9QH73JoCxLYNjipEn1SHkWWfvsryrNCSbh8gBvfe" \
                                   "Tg5CrqqTpsEQZFBUxH8NuQ5EJz8EDHC261tgtvnfBNze2Jteoxhi47"

    assert path_xkey_to_bip32_xkey("yprvAJXHiBz6oBHZouVo25rgayS7ss1FGAkAsPMrtpTX7DrAHqocTrus"
                                   "QmMNuA2VoJyxJ9jsfAQFRFoRrDFKAhNoVgvhLYSZ5LWqQJy7fYUzRW8") == \
                                   "xprv9yh2QXKBeVk5xcJgBj54NtLchtroKYkfxGqe7RZdjDUHEjzPDCkJ" \
                                   "nhhEsx4uoQL2tWd4ugogxbSsxvdkSzxnhTF6UCk8VRhM8auUGwuyZMC"

    assert path_xkey_to_bip32_xkey("uprv8tXDerPXZ1QsWSbPwQ6RR3S3YhsGBPzwCs2jTKmkMrk5VhWMvr6E"
                                   "GXLDE4oRTjX9pCMzERsgqZkd7bbgwuhCpKhVZEdDF6CUukNY3RLytkD") == \
                                   "tprv8ZgxMBicQKsPf9QH73JoCxLYNjipEn1SHkWWfvsryrNCSbh8gBvfe" \
                                   "Tg5CrqqTpsEQZFBUxH8NuQ5EJz8EDHC261tgtvnfBNze2Jteoxhi47"

    assert path_xkey_to_bip32_xkey("zprvAc4DSBwiaXyw2RdtM1CDXgzUe4BMm6K33G91Dr8PHCx8LiJLW8jY"
                                   "tUpdfrjuDy9ega3Pyg3xiNiEZCL3hSw1JWRzKxnz7k9hsnsH8R1Ckwk") == \
                                   "xprv9xPgprbtHAtyKqFegHcy7WoUJ7tTsrL3D36Zf4LcXCCNEWfszpQR" \
                                   "eMWMdSpjE9qosHonUirqo418nd6vG46yi34nbHQ8wvWjLLjzMBFKNqM"

    assert path_xkey_to_bip32_xkey("vprv9DMUxX4ShgxMMjnWmkt3d8XYig1i81zS7yYxEifdjs7xYoKbBWFnta"
                                   "zMFGm1TeB5DqUnyuUFJE7AztDFfc7DcZP6RaKdq11yBUSBRvwZLXe",
                                   hex=True) == \
                                   decode_base58("tprv8ZgxMBicQKsPf9QH73JoCxLYNjipEn1SHkWWfvsryrNCSbh8gBvfe" \
                                                 "Tg5CrqqTpsEQZFBUxH8NuQ5EJz8EDHC261tgtvnfBNze2Jteoxhi47",
                                                 checksum=True).hex()

    assert path_xkey_to_bip32_xkey("vprv9DMUxX4ShgxMMjnWmkt3d8XYig1i81zS7yYxEifdjs7xYoKbBWFnta"
                                   "zMFGm1TeB5DqUnyuUFJE7AztDFfc7DcZP6RaKdq11yBUSBRvwZLXe",
                                   base58=False) == \
                                   decode_base58("tprv8ZgxMBicQKsPf9QH73JoCxLYNjipEn1SHkWWfvsryrNCSbh8gBvfe" \
                                                 "Tg5CrqqTpsEQZFBUxH8NuQ5EJz8EDHC261tgtvnfBNze2Jteoxhi47",
                                                 checksum=True)


def test_bip32_xkey_to_path_xkey():
    assert bip32_xkey_to_path_xkey(decode_base58("xpub68isDcaF29MCeYMdJ6ZypmjogsM6bgx3ssCZyRyT4JYqPZcSkEQtKx6ag1FHnir"
                                   "P8tz9VNAn7cuJhBKf63ijyw1FPg2Po36TcuX725Mom1X", checksum=True), "BIP44") == \
                                   "xpub68isDcaF29MCeYMdJ6ZypmjogsM6bgx3ssCZyRyT4JYqPZcSkEQtKx6ag1FHnir" \
                                   "P8tz9VNAn7cuJhBKf63ijyw1FPg2Po36TcuX725Mom1X"
    assert bip32_xkey_to_path_xkey(decode_base58("xpub68isDcaF29MCeYMdJ6ZypmjogsM6bgx3ssCZyRyT4JYqPZcSkEQtKx6ag1FHnir"
                                   "P8tz9VNAn7cuJhBKf63ijyw1FPg2Po36TcuX725Mom1X", checksum=True).hex(), "BIP44") == \
                                   "xpub68isDcaF29MCeYMdJ6ZypmjogsM6bgx3ssCZyRyT4JYqPZcSkEQtKx6ag1FHnir" \
                                   "P8tz9VNAn7cuJhBKf63ijyw1FPg2Po36TcuX725Mom1X"

    assert bip32_xkey_to_path_xkey("tpubD6NzVbkrYhZ4YcS4zgyPcMzewmEkQ7CLs47HxSvAQ8AbH5wuJakFpxHwNyXDSmS"
                                   "DzNQmkKx2unk3xTDNN716cAKbgr6CyPm3hsAW4CqPVK2", "BIP44") == \
                                   "tpubD6NzVbkrYhZ4YcS4zgyPcMzewmEkQ7CLs47HxSvAQ8AbH5wuJakFpxHwNyXDSmS" \
                                   "DzNQmkKx2unk3xTDNN716cAKbgr6CyPm3hsAW4CqPVK2"

    assert bip32_xkey_to_path_xkey("xpub68isDcaF29MCeYMdJ6ZypmjogsM6bgx3ssCZyRyT4JYqPZcSkEQtKx6ag1FHnir"
                                   "P8tz9VNAn7cuJhBKf63ijyw1FPg2Po36TcuX725Mom1X", "BIP49") == \
                                   "ypub6TZ8XHFAAptgVqYk8TMc2rqJrqVYYJwYnyinkpsLSJviSfRfztaSx1kihDCsndW" \
                                   "JYY6xEqmLaHFraTwDok8knAgrG1ipNwuwtdakQibcvzB"

    assert bip32_xkey_to_path_xkey("tpubD6NzVbkrYhZ4YcS4zgyPcMzewmEkQ7CLs47HxSvAQ8AbH5wuJakFpxHwNyXDSmS"
                                   "DzNQmkKx2unk3xTDNN716cAKbgr6CyPm3hsAW4CqPVK2", "BIP49") == \
                                   "upub57Wa4MvRPNyAivfs3RdRnBNn6jhkarina5xLFiBMvCH4NVqWUPQUpKeh5KZfvYXD" \
                                   "yYXStKeUzhrMcQt4p9upL1pW2EFdY8eMJjPA8UKuxaL"

    assert bip32_xkey_to_path_xkey("xpub68isDcaF29MCeYMdJ6ZypmjogsM6bgx3ssCZyRyT4JYqPZcSkEQtKx6ag1FHnirP"
                                   "8tz9VNAn7cuJhBKf63ijyw1FPg2Po36TcuX725Mom1X", "BIP84") == \
                                   "zpub6nPPpwv5KWSAM8jrxp9EEwvp2odzUvw3i6F1YDmDpKJbVmEuFYk1a5QriRATnYAD" \
                                   "xBDkzKMu2wcQTkYnXSYmaQNT8MRExrjSAMePoDv2d2R"

    assert bip32_xkey_to_path_xkey("tpubD6NzVbkrYhZ4YcS4zgyPcMzewmEkQ7CLs47HxSvAQ8AbH5wuJakFpxHwNyXDSmSD"
                                   "zNQmkKx2unk3xTDNN716cAKbgr6CyPm3hsAW4CqPVK2", "BIP84") == \
                                   "vpub5SLqN2bLY4WeaDrysnR3zGUHGhrCXUiHVCUZ375FJCewRbejj3a3SPJq6XXFvTB9P" \
                                   "BeFdoF3TNCuVhVdXrKq8FW6tZx483TqaTSoWx3U88j"

    assert bip32_xkey_to_path_xkey("xprv9xPgprbtHAtyKqFegHcy7WoUJ7tTsrL3D36Zf4LcXCCNEWfszpQReMWMdSpjE9qos"
                                   "HonUirqo418nd6vG46yi34nbHQ8wvWjLLjzMBFKNqM", "BIP44") == \
                                   "xprv9xPgprbtHAtyKqFegHcy7WoUJ7tTsrL3D36Zf4LcXCCNEWfszpQReMWMdSpjE9qos" \
                                   "HonUirqo418nd6vG46yi34nbHQ8wvWjLLjzMBFKNqM"

    assert bip32_xkey_to_path_xkey("tprv8ZgxMBicQKsPf9QH73JoCxLYNjipEn1SHkWWfvsryrNCSbh8gBvfeTg5CrqqTpsEQ"
                                   "ZFBUxH8NuQ5EJz8EDHC261tgtvnfBNze2Jteoxhi47", "BIP44") == \
                                   "tprv8ZgxMBicQKsPf9QH73JoCxLYNjipEn1SHkWWfvsryrNCSbh8gBvfeTg5CrqqTpsEQ" \
                                   "ZFBUxH8NuQ5EJz8EDHC261tgtvnfBNze2Jteoxhi47"

    assert bip32_xkey_to_path_xkey("xprv9xPgprbtHAtyKqFegHcy7WoUJ7tTsrL3D36Zf4LcXCCNEWfszpQReMWMdSpjE9qos"
                                   "HonUirqo418nd6vG46yi34nbHQ8wvWjLLjzMBFKNqM", "BIP49") == \
                                   "yprvAHDx8XGoRrSTB8SmWeQbKbtyU62upUKY89cnSTEVuCaFHcV7FUZzGRAVeenKE4VjG" \
                                   "vvbECTQFiMgfuiUykWzWGkPTd6ZXqLDc4odjkNZA2Z"

    assert bip32_xkey_to_path_xkey("tprv8ZgxMBicQKsPf9QH73JoCxLYNjipEn1SHkWWfvsryrNCSbh8gBvfeTg5CrqqTpsEQ"
                                   "ZFBUxH8NuQ5EJz8EDHC261tgtvnfBNze2Jteoxhi47", "BIP49") == \
                                   "uprv8tXDerPXZ1QsWSbPwQ6RR3S3YhsGBPzwCs2jTKmkMrk5VhWMvr6EGXLDE4oRTjX9p" \
                                   "CMzERsgqZkd7bbgwuhCpKhVZEdDF6CUukNY3RLytkD"

    assert bip32_xkey_to_path_xkey("xprv9xPgprbtHAtyKqFegHcy7WoUJ7tTsrL3D36Zf4LcXCCNEWfszpQReMWMdSpjE9qos"
                                   "HonUirqo418nd6vG46yi34nbHQ8wvWjLLjzMBFKNqM", "BIP84") == \
                                   "zprvAc4DSBwiaXyw2RdtM1CDXgzUe4BMm6K33G91Dr8PHCx8LiJLW8jYtUpdfrjuDy9eg" \
                                   "a3Pyg3xiNiEZCL3hSw1JWRzKxnz7k9hsnsH8R1Ckwk"

    assert bip32_xkey_to_path_xkey("tprv8ZgxMBicQKsPf9QH73JoCxLYNjipEn1SHkWWfvsryrNCSbh8gBvfeTg5CrqqTpsEQ"
                                   "ZFBUxH8NuQ5EJz8EDHC261tgtvnfBNze2Jteoxhi47", "BIP84", hex=True) == \
                                   decode_base58("vprv9DMUxX4ShgxMMjnWmkt3d8XYig1i81zS7yYxEifdjs7xYoKbBWF"
                                                 "ntazMFGm1TeB5DqUnyuUFJE7AztDFfc7DcZP6RaKdq11yBUSBRvwZLXe",
                                                 checksum=True).hex()

    assert bip32_xkey_to_path_xkey("tprv8ZgxMBicQKsPf9QH73JoCxLYNjipEn1SHkWWfvsryrNCSbh8gBvfeTg5CrqqTpsEQ"
                                   "ZFBUxH8NuQ5EJz8EDHC261tgtvnfBNze2Jteoxhi47", "BIP84", base58=False) == \
                                   decode_base58("vprv9DMUxX4ShgxMMjnWmkt3d8XYig1i81zS7yYxEifdjs7xYoKbBWF"
                                                 "ntazMFGm1TeB5DqUnyuUFJE7AztDFfc7DcZP6RaKdq11yBUSBRvwZLXe",
                                                 checksum=True)
    with pytest.raises(ValueError):
        bip32_xkey_to_path_xkey("tprv8ZgxMBicQKsPf9QH73JoCxLYNjipEn1SHkWWfvsryrNCSbh8gBvfeTg5CrqqTpsEQ"
                                "ZFBUxH8NuQ5EJz8EDHC261tgtvnfBNze2Jteoxhi47", "BIP88")
    with pytest.raises(ValueError):
        bip32_xkey_to_path_xkey("kjsdhfkjzxzvx][ewhf34h8322u32oeu2oh2", "BIP84")

    with pytest.raises(ValueError):
        bip32_xkey_to_path_xkey(decode_base58("pprv9xPgprbtHAtyKqFegHcy7WoUJ7tTsrL3D36Zf4LcXCCNEWfszpQReMWMdSpjE9qos"
                                "HonUirqo418nd6vG46yi34nbHQ8wvWjLLjzMBFKNqM", checksum=True), "BIP84")
