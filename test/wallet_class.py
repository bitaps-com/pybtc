import unittest
import os
import sys


parentPath = os.path.abspath("..")
if parentPath not in sys.path:
    sys.path.insert(0, parentPath)

from pybtc import  Wallet

class AddressClassTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("\nTesting address class:\n")

    def test_is_wallet_menmonic(self):
        # assert_equal(change_addrV["hdkeypath"], "m/0'/1'/0'") #first internal child key
        # mainnet
        m = "rally skirt common ski shiver enrich blame armor eternal waste pledge slim " \
            "accuse faith link define same hello private satisfy million sand drum thought"
        xpub44 = "xpub6BgdVexnSSSXPDf1mXjEnvnsjkvqE2ufWt8Te34ii2n8rSbwcxGbYmUrpS2wtqH7jz2qUzN" \
                 "1uicqgZUcsXmtHFgygh1Q9yiP9xi3oLnF5PZ"
        xpriv44 = "xprv9xhH69Rtc4tEAjaYfWCERnr9Bj6LpaBp9fCrqef79hF9yeGo5QxLzyANy9RnmZ3qeVw92j" \
                  "7TcyieNHQxkCwZn2oYeQR7xYpa3YWyjWpdGdt"
        xpriv44t = "tprv8ZgxMBicQKsPdBaCwmYRjxvkaBRUG1pv5KnBHqKyrTr8VhVzxs28b88jx6TF96M6ehYHBD" \
                   "aZ1Czwf6udxuFbe9gMCMQLL7SHQ5467ocadBd"

        xpriv44root = "xprv9s21ZrQH143K2NLgHCgvaKJmG41G2Vnujms4RQuXNVMei6kuyVgP5NmJ2vHb8ixnHG1WB" \
                      "7xnqrR9CFMtqgueq6QkfiC2fkiEUyJfg6khJJN"

        a44_0 = "14kh1WtCv8S6UqWG4XBaiXfnBWRhhjWUBA"
        a44_1 = "15jfBWnfPAkTUiv4oiKrc3GPAHNQwdqase"
        a44_2 = "1CRdXbbz67EceudM5vSTXU2gAXN39ieQjk"
        a44_3 = "1KUB9Ms1ynjUE1r1HTmsgkTUMTs3r1F9Vj"
        a44_19 = "12UVi5ePMxZZmRo2nJikXhgdCapkBKyukK"
        a44_19_i = "18bPQpTmKa66ewQjK4L5k7sjYBMD8BiqXp"

        p44_0 = "L23zUE7Q2wasVjo3Ew4KDonsZAGETnBYksr9ofPwt7FbQho4urjY"
        p44_1 = "Kzzmh4SVAPadoXXoc6k3WdKrP8weynJCdGhvmRRduerrnpSEAaH7"
        p44_2 = "L4ds5yBV6EnmwMntnoTTWKWPfag3kUnMQoe7XyPGRGcG8xTeXD32"
        p44_3 = "L38hLqdkHnq9vXaP1yGfXDESvxJEAooNmmgnbR58KXLnb5sVdYJd"
        p44_19 = "L3X8qmiPaFEog9Y66EHke7ar6HFhSuBrvTS8K1NxAwVSEXQLQsVp"

        p_44_19_i = "KxEVF2YFgaSBE2zqNyK71iGFuCQ3hGyGD1wa4zzgHHMN85kG3FHX"


        a44_0_t = "mjGeJZyBj9sMFwysn69xYSt73W2Qb9hfwo"
        a44_19_t = "mgzT18jNAyzpYYGeVsh8Mctx4aRT7rMkSL"
        a44_19_i_t = "mo7LhsYk8bXMS3tM2dJTa364QAwv25Xxo4"

        w = Wallet(m, path_type="BIP44", testnet=True)
        self.assertEqual(w.get_address(0)["address"], a44_0_t)
        self.assertEqual(w.get_address(19)["address"], a44_19_t)
        self.assertEqual(w.get_address(19, chain="internal")["address"], a44_19_i_t)


        w = Wallet(m, path_type="BIP44")
        self.assertEqual(w.testnet, False)
        self.assertEqual(w.account_public_xkey, xpub44)
        self.assertEqual(w.account_private_xkey, xpriv44)
        self.assertEqual(w.get_address(0)["address"], a44_0)
        self.assertEqual(w.get_address(1)["address"], a44_1)
        self.assertEqual(w.get_address(2)["address"], a44_2)
        self.assertEqual(w.get_address(3)["address"], a44_3)
        self.assertEqual(w.get_address(19)["address"], a44_19)
        self.assertEqual(w.get_address(0)["private_key"], p44_0)
        self.assertEqual(w.get_address(1)["private_key"], p44_1)
        self.assertEqual(w.get_address(2)["private_key"], p44_2)
        self.assertEqual(w.get_address(3)["private_key"], p44_3)
        self.assertEqual(w.get_address(19)["private_key"], p44_19)
        self.assertEqual(w.get_address(19, chain="internal")["private_key"], p_44_19_i)

        w2 = Wallet(xpub44)
        self.assertEqual(w2.testnet, False)
        self.assertEqual(w2.account_public_xkey, xpub44)
        self.assertEqual(w2.account_private_xkey, None)
        self.assertEqual(w2.get_address(0)["address"], a44_0)
        self.assertEqual(w2.get_address(1)["address"], a44_1)
        self.assertEqual(w2.get_address(2)["address"], a44_2)
        self.assertEqual(w2.get_address(3)["address"], a44_3)
        self.assertEqual(w2.get_address(19)["address"], a44_19)
        self.assertEqual(w2.get_address(19, chain="internal")["address"], a44_19_i)

        wt = Wallet(xpriv44t)
        self.assertEqual(wt.testnet, True)
        self.assertEqual(wt.get_address(0)["address"], a44_0_t)
        self.assertEqual(wt.get_address(19)["address"], a44_19_t)
        self.assertEqual(wt.get_address(19, chain="internal")["address"], a44_19_i_t)

        w3 = Wallet(xpriv44, path_type="BIP44")
        self.assertEqual(w3.testnet, False)
        self.assertEqual(w3.account_public_xkey, xpub44)
        self.assertEqual(w3.account_private_xkey, xpriv44)
        self.assertEqual(w3.get_address(0)["address"], a44_0)
        self.assertEqual(w3.get_address(1)["address"], a44_1)
        self.assertEqual(w3.get_address(2)["address"], a44_2)
        self.assertEqual(w3.get_address(3)["address"], a44_3)
        self.assertEqual(w3.get_address(19)["address"], a44_19)
        self.assertEqual(w3.get_address(0)["private_key"], p44_0)
        self.assertEqual(w3.get_address(1)["private_key"], p44_1)
        self.assertEqual(w3.get_address(2)["private_key"], p44_2)
        self.assertEqual(w3.get_address(3)["private_key"], p44_3)
        self.assertEqual(w3.get_address(19)["private_key"], p44_19)
        self.assertEqual(w3.get_address(19, chain="internal")["private_key"], p_44_19_i)

        w3 = Wallet(xpriv44)
        self.assertEqual(w3.testnet, False)
        self.assertEqual(w3.account_public_xkey, xpub44)
        self.assertEqual(w3.account_private_xkey, xpriv44)
        self.assertEqual(w3.get_address(0)["address"], a44_0)
        self.assertEqual(w3.get_address(1)["address"], a44_1)
        self.assertEqual(w3.get_address(2)["address"], a44_2)
        self.assertEqual(w3.get_address(3)["address"], a44_3)
        self.assertEqual(w3.get_address(19)["address"], a44_19)
        self.assertEqual(w3.get_address(0)["private_key"], p44_0)
        self.assertEqual(w3.get_address(1)["private_key"], p44_1)
        self.assertEqual(w3.get_address(2)["private_key"], p44_2)
        self.assertEqual(w3.get_address(3)["private_key"], p44_3)
        self.assertEqual(w3.get_address(19)["private_key"], p44_19)
        self.assertEqual(w3.get_address(19, chain="internal")["private_key"], p_44_19_i)

        w3 = Wallet(xpriv44root)
        self.assertEqual(w3.testnet, False)
        self.assertEqual(w3.account_public_xkey, xpub44)
        self.assertEqual(w3.account_private_xkey, xpriv44)
        self.assertEqual(w3.get_address(0)["address"], a44_0)
        self.assertEqual(w3.get_address(1)["address"], a44_1)
        self.assertEqual(w3.get_address(2)["address"], a44_2)
        self.assertEqual(w3.get_address(3)["address"], a44_3)
        self.assertEqual(w3.get_address(19)["address"], a44_19)
        self.assertEqual(w3.get_address(0)["private_key"], p44_0)
        self.assertEqual(w3.get_address(1)["private_key"], p44_1)
        self.assertEqual(w3.get_address(2)["private_key"], p44_2)
        self.assertEqual(w3.get_address(3)["private_key"], p44_3)
        self.assertEqual(w3.get_address(19)["private_key"], p44_19)
        self.assertEqual(w3.get_address(19, chain="internal")["private_key"], p_44_19_i)


        xpub49 = "ypub6Wxm6Wp2UwckK3bv1DRcuEzxbnaSqT9MVV3tFZGhZYRgNdBPoiBcPwA8TDX9EoDfkztSgqeX" \
                 "fJPSk3PQMt4inLH4hzsjbob81kmy8oQFHkx"
        xpriv49 = "yprvAHyQh1H8ea4T6ZXSuBtcY74E3kjxRzRW8G8HTAs61CthVprFGAsMr8qebvGZM9G99qXVtocg" \
                  "LtZjRZC4iS9L1ovJ8TEfLVs8nN5ahZJpkGm"

        xpriv49root = "yprvABrGsX5C9jansfXo7ZUYnQQGS29hy7nQetPHCooQkVjXmCa9E9qwhSRS48FB8dchgu8Jv" \
                      "bZMJWmh5XyTZPKfdL6MY3tTFfXikhNK4iprszc"

        a49_0 = "3KDC6ugKwrxGLsTKfEoQY79GooVGtyCj6p"
        a49_1 = "3CqYvv5NShfJihWpp3mvikzJAq2DrDrywR"
        a49_2 = "3LcotDRszCGkgCBiUYxUZ1tZeWTQ7AgV6N"
        a49_3 = "35GTWtRp9Xypn6UFECrwBF5qa8vsbLeanb"
        a49_19 = "3MWHqhd7tcY2MUucd4xbTZBNJS8DTTteuq"
        a49_19_i = "3AHmLTefeW12yp4CiRPK2Q1mEUwMzYQWLH"

        p49_0 = "KyjKJyyJPgqCyxqMjkBLFg6KboQvsChE82KkuuYZQVFGjQAPN4v2"
        p49_1 = "KxJLTnrsNkgFYYeA1R5GCpfxnaLVbeSPYjiVWnJkjz4anTaCXdti"
        p49_2 = "L36ZqLCpWv9mcX3eG7q59mfe5yhjfP1GoSWtBMU6GDyHNnJ2CqkE"
        p49_3 = "KxVArb2SPBJKXftppVg8JUS6zdf5EMBRJ87KZKv1HDf5wDF8t3kv"
        p49_19 = "KwV6ztbWQHxkUhrpmqVuV9xgqahx4jHxHwfUeNx1HQhjQXSQAhq2"

        p_49_19_i = "L3PDN7Hs2CtBG78f2BkvXA6B2zRn9dfPf9S1KXN2tAEVfY9LdpqY"

        w = Wallet(m, path_type="BIP49")
        self.assertEqual(w.testnet, False)
        self.assertEqual(w.account_public_xkey, xpub49)
        self.assertEqual(w.account_private_xkey, xpriv49)

        self.assertEqual(w.get_address(0)["address"], a49_0)
        self.assertEqual(w.get_address(1)["address"], a49_1)
        self.assertEqual(w.get_address(2)["address"], a49_2)
        self.assertEqual(w.get_address(3)["address"], a49_3)
        self.assertEqual(w.get_address(19)["address"], a49_19)
        self.assertEqual(w.get_address(0)["private_key"], p49_0)
        self.assertEqual(w.get_address(1)["private_key"], p49_1)
        self.assertEqual(w.get_address(2)["private_key"], p49_2)
        self.assertEqual(w.get_address(3)["private_key"], p49_3)
        self.assertEqual(w.get_address(19)["private_key"], p49_19)
        self.assertEqual(w.get_address(19, chain="internal")["private_key"], p_49_19_i)

        w2 = Wallet(xpub49)
        self.assertEqual(w2.testnet, False)
        self.assertEqual(w2.account_public_xkey, xpub49)
        self.assertEqual(w2.account_private_xkey, None)
        self.assertEqual(w2.get_address(0)["address"], a49_0)
        self.assertEqual(w2.get_address(1)["address"], a49_1)
        self.assertEqual(w2.get_address(2)["address"], a49_2)
        self.assertEqual(w2.get_address(3)["address"], a49_3)
        self.assertEqual(w2.get_address(19)["address"], a49_19)
        self.assertEqual(w2.get_address(19, chain="internal")["address"], a49_19_i)

        w3 = Wallet(xpriv49)
        self.assertEqual(w3.testnet, False)
        self.assertEqual(w3.account_public_xkey, xpub49)
        self.assertEqual(w3.account_private_xkey, xpriv49)
        self.assertEqual(w3.get_address(0)["address"], a49_0)
        self.assertEqual(w3.get_address(1)["address"], a49_1)
        self.assertEqual(w3.get_address(2)["address"], a49_2)
        self.assertEqual(w3.get_address(3)["address"], a49_3)
        self.assertEqual(w3.get_address(19)["address"], a49_19)
        self.assertEqual(w3.get_address(0)["private_key"], p49_0)
        self.assertEqual(w3.get_address(1)["private_key"], p49_1)
        self.assertEqual(w3.get_address(2)["private_key"], p49_2)
        self.assertEqual(w3.get_address(3)["private_key"], p49_3)
        self.assertEqual(w3.get_address(19)["private_key"], p49_19)
        self.assertEqual(w3.get_address(19, chain="internal")["private_key"], p_49_19_i)

        w3 = Wallet(xpriv49root)
        self.assertEqual(w3.testnet, False)
        self.assertEqual(w3.account_public_xkey, xpub49)
        self.assertEqual(w3.account_private_xkey, xpriv49)
        self.assertEqual(w3.get_address(0)["address"], a49_0)
        self.assertEqual(w3.get_address(1)["address"], a49_1)
        self.assertEqual(w3.get_address(2)["address"], a49_2)
        self.assertEqual(w3.get_address(3)["address"], a49_3)
        self.assertEqual(w3.get_address(19)["address"], a49_19)
        self.assertEqual(w3.get_address(0)["private_key"], p49_0)
        self.assertEqual(w3.get_address(1)["private_key"], p49_1)
        self.assertEqual(w3.get_address(2)["private_key"], p49_2)
        self.assertEqual(w3.get_address(3)["private_key"], p49_3)
        self.assertEqual(w3.get_address(19)["private_key"], p49_19)
        self.assertEqual(w3.get_address(19, chain="internal")["private_key"], p_49_19_i)


        xpub84 = "zpub6rhSjy3XXQKAh6aBPXKMPa56gsSmPFb8rKh94uZa4fgncTLXsdRWq3Ur9BAoFSa8BXJ79ST5Hz" \
                 "Krxx8M3jBYsTnsE9E3CcpQ8vhKAP684ta"
        xpriv84 = "zprvAdi6LTWdh2ksUcViHVnM2S8N8qcGynsHV6mYGX9xWL9ojf1PL67GHFANHvoLm4J41hGT8QGR" \
                  "vDNUeEnNw16Xh9ZpYvvatwmaTCjMnRnuKp7"

        xpriv84root = "zprvAWgYBBk7JR8GixiuwvGAzVVmbzJ9ujmuZzuVzChJ8W7QpJPNUp1WKW5a5LCm8YGd6YF7g5" \
                      "9umB8Expb2H5jgRZmxQPasqaMD2RRxTDiBj3B"

        a84_0 = "bc1qktswv5qw0af9hzc87ql6vhgdh5m3kmpz9py3uh"
        a84_1 = "bc1qwffx8huf8wwwpt6u0vh3z4sst5p9jpmvf8jkpf"
        a84_2 = "bc1q3e6gfa4lvrl5p74ug5hkjukvq2gn22l08h2ng0"
        a84_3 = "bc1q8wljecft5hkv2u9hql0244v3gee504pvat7w4m"
        a84_19 = "bc1qha4un56xlhvyxld365jhqqdrg7dfnf86py66fx"
        a84_19_i = "bc1q0ll86xmwvk6uy9e3x9qn92dyfn9mwdepjmva8p"

        p84_0 = "Kx1cq5txr9q1ohyzWkA4LUgZvjqbokpd7UBoGvnWwwveGfP6p4YJ"
        p84_1 = "KztQibwvHLfZHz2wBcX6AiLmAyCvfFJxfsAKFSMgpuvHEsG22r8z"
        p84_2 = "L4y7iw2kUu5PdoqSRZ8wX7oVNnMkZquZRVnKb2KLjGpVvrgMJ4cB"
        p84_3 = "L3n2KAM1DaM9uMY2AKLsyqe8TFTHm6gYjzWjVjCS42ocPwpbApfK"
        p84_19 = "L21r2kT3GxpK7kRBWZ5EFVrRYEzvSLWpxnLEC4drWbBjNrDAR69Y"

        p_84_19_i = "Kx1wszVqpRytaaH2rXwntBr39vLSNPeW8jhqiBmAf6gAvbQbHQcy"

        w = Wallet(m, path_type="BIP84")
        self.assertEqual(w.testnet, False)
        self.assertEqual(w.account_public_xkey, xpub84)
        self.assertEqual(w.account_private_xkey, xpriv84)

        self.assertEqual(w.get_address(0)["address"], a84_0)
        self.assertEqual(w.get_address(1)["address"], a84_1)
        self.assertEqual(w.get_address(2)["address"], a84_2)
        self.assertEqual(w.get_address(3)["address"], a84_3)
        self.assertEqual(w.get_address(19)["address"], a84_19)
        self.assertEqual(w.get_address(0)["private_key"], p84_0)
        self.assertEqual(w.get_address(1)["private_key"], p84_1)
        self.assertEqual(w.get_address(2)["private_key"], p84_2)
        self.assertEqual(w.get_address(3)["private_key"], p84_3)
        self.assertEqual(w.get_address(19)["private_key"], p84_19)
        self.assertEqual(w.get_address(19, chain="internal")["private_key"], p_84_19_i)

        w2 = Wallet(xpub84)
        self.assertEqual(w2.testnet, False)
        self.assertEqual(w2.account_public_xkey, xpub84)
        self.assertEqual(w2.account_private_xkey, None)
        self.assertEqual(w2.get_address(0)["address"], a84_0)
        self.assertEqual(w2.get_address(1)["address"], a84_1)
        self.assertEqual(w2.get_address(2)["address"], a84_2)
        self.assertEqual(w2.get_address(3)["address"], a84_3)
        self.assertEqual(w2.get_address(19)["address"], a84_19)
        self.assertEqual(w2.get_address(19, chain="internal")["address"], a84_19_i)

        w3 = Wallet(xpriv84)
        self.assertEqual(w3.testnet, False)
        self.assertEqual(w3.account_public_xkey, xpub84)
        self.assertEqual(w3.account_private_xkey, xpriv84)
        self.assertEqual(w3.get_address(0)["address"], a84_0)
        self.assertEqual(w3.get_address(1)["address"], a84_1)
        self.assertEqual(w3.get_address(2)["address"], a84_2)
        self.assertEqual(w3.get_address(3)["address"], a84_3)
        self.assertEqual(w3.get_address(19)["address"], a84_19)
        self.assertEqual(w3.get_address(0)["private_key"], p84_0)
        self.assertEqual(w3.get_address(1)["private_key"], p84_1)
        self.assertEqual(w3.get_address(2)["private_key"], p84_2)
        self.assertEqual(w3.get_address(3)["private_key"], p84_3)
        self.assertEqual(w3.get_address(19)["private_key"], p84_19)
        self.assertEqual(w3.get_address(19, chain="internal")["private_key"], p_84_19_i)

        w3 = Wallet(xpriv84root)
        self.assertEqual(w3.testnet, False)
        self.assertEqual(w3.account_public_xkey, xpub84)
        self.assertEqual(w3.account_private_xkey, xpriv84)
        self.assertEqual(w3.get_address(0)["address"], a84_0)
        self.assertEqual(w3.get_address(1)["address"], a84_1)
        self.assertEqual(w3.get_address(2)["address"], a84_2)
        self.assertEqual(w3.get_address(3)["address"], a84_3)
        self.assertEqual(w3.get_address(19)["address"], a84_19)
        self.assertEqual(w3.get_address(0)["private_key"], p84_0)
        self.assertEqual(w3.get_address(1)["private_key"], p84_1)
        self.assertEqual(w3.get_address(2)["private_key"], p84_2)
        self.assertEqual(w3.get_address(3)["private_key"], p84_3)
        self.assertEqual(w3.get_address(19)["private_key"], p84_19)
        self.assertEqual(w3.get_address(19, chain="internal")["private_key"], p_84_19_i)

