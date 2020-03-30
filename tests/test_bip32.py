import pytest

from pybtc.functions.encode import decode_base58
from pybtc.functions.bip32 import xprivate_to_xpublic_key
from pybtc.functions.bip32 import create_master_xprivate_key
from pybtc.functions.bip39_mnemonic import mnemonic_to_seed
from pybtc.functions.bip39_mnemonic import entropy_to_mnemonic


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