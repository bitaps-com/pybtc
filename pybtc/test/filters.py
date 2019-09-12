import unittest
import os, sys
parentPath = os.path.abspath("..")
if parentPath not in sys.path:
    sys.path.insert(0, parentPath)
from pybtc import *
import random

def split_len(seq, length):
    return [seq[i:i+length] for i in range(0, len(seq), length)]


class FilterFunctionsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("\nTesting filter functions:\n")


    def test_bloom_filter11(self):
        print("test gcs11")


        m_addresses = set()
        while len(m_addresses) < 10_000:
            i = siphash(sha256(int_to_bytes(random.randint(1, 0xFFFFFFFFFFFFFFFFFFFF)))[:21])
            m_addresses.add(i)
        print("m addresses created ", len(m_addresses))

        f2 = create_test_filter(m_addresses)

        print("filter len ", len(f2)/ 1024 / 1024)
        return
        size = 0
        for c in range(10):
            et = 0
            for fi in range(2000):
                f2 = create_gcs(m_addresses, N=7332, v_0= fi)
                l2 = set(decode_gcs(f2, len(m_addresses)))
                b_addresses = set()
                w = 7332
                while len(b_addresses) < w:
                    r = sha256(int_to_bytes(random.randint(1, 0xFFFFFFFFFFFFFFFFFFFF)))[:21]

                    if r not in m_addresses:
                        b_addresses.add(r)


                f = create_gcs(b_addresses, v_0=fi)
                print("blocks addresses created ", len(b_addresses), "filter size", len(f))

                l = set(decode_gcs(f, len(b_addresses)))
                size += len(f)
                e = 0
                for q in l2:
                    if q in l:
                        e += 1
                if e:
                    et+=1
                print(" false positive =", e)
            print(c,":", "2000 blocks","false positive count:", et)


        import zlib
        print("",len(f))
        print("",len(zlib.compress(f)))



    def test_bloom_filter(self):
        return
        print("test gcs")
        b_addresses = set()
        while len(b_addresses) < 10_000:
            b_addresses.add(sha256(int_to_bytes(random.randint(1, 0xFFFFFFFFFFFFFFFFFFFF)))[:21])
        print("blocks addresses created ")
        f = create_gcs(b_addresses, N = 10_000, M=54975581, P=25)
        l = decode_gcs(f, len(b_addresses),P=25)
        print("blocks set created ", len(f))

        m_addresses = set()
        while len(m_addresses) < 10000:
            i = sha256(int_to_bytes(random.randint(1, 0xFFFFFFFFFFFFFFFFFFFF)))[:21]
            if i not in b_addresses:
                m_addresses.add(i)
        print("m addresses created ")
        f2 = create_gcs(m_addresses, N = 10_000, M=54975581, P=25)
        l2 = decode_gcs(f2, len(m_addresses), P=25)
        print("m set created ")
        e = 0
        for i in l2:
            if i in l:
                e += 1

        print(" exist =", e)


        import zlib
        print("",len(f))
        print("",len(zlib.compress(f)))


    def test_bloom_gcs_1000000(self):
        return
        print("GCS filter 20 000 elements vs 1 000 000 monitoring addresses:")

        print("generate address set ...")
        addresses = set()
        while len(addresses) < 1_000_000:
            addresses.add(sha256(int_to_bytes(random.randint(1, 0xFFFFFFFFFFFFFFFFFFFF)))[:21])

        print("Test false positive rate for 2000 blocks:")

        blocks_affected = 0
        q = 0
        for i in range(2000):

            block_addresses = set()
            while len(block_addresses) < 20_000:
                a = sha256(int_to_bytes(random.randint(1, 0xFFFFFFFFFFFFFFFFFFFF)))[:21]
                if a in addresses:
                    continue
                block_addresses.add(a)

            # create bloom filter
            f, h = create_bloom_filter(20_000, 1 / 5_000_000, max_bit_size=0)
            for a in block_addresses:
                insert_to_bloom_filter(f, a, h)


            positive = 0
            t = time.time()
            for a in addresses:
                if contains_in_bloom_filter(f, a, h):
                    positive += 1
            t = time.time() - t
            q += t
            print("Block", i, "false positive", positive, "filter size", len(f), "time", t)
            if positive:
                blocks_affected += 1
        print("False positive blocks", blocks_affected, "from 2000", "time", q)

        print("Test false negative:")
        negative = 0
        for a in addresses:
            if not contains_in_bloom_filter(f, a, h):
                negative += 1
        print("False negative ", negative)
        print("Filter bytes per address ", len(f) / 20_000)


    def test_bloom_filter_fpr_20000_1000000(self):
        return
        print("Bloom filter 20 000 elements vs 1 000 000 monitoring addresses:")

        print("generate address set ...")
        addresses = set()
        while len(addresses) < 1_000_000:
            addresses.add(sha256(int_to_bytes(random.randint(1, 0xFFFFFFFFFFFFFFFFFFFF)))[:21])

        print("Test false positive rate for 2000 blocks:")

        blocks_affected = 0
        q = 0
        for i in range(2000):

            block_addresses = set()
            while len(block_addresses) < 20_000:
                a = sha256(int_to_bytes(random.randint(1, 0xFFFFFFFFFFFFFFFFFFFF)))[:21]
                if a in addresses:
                    continue
                block_addresses.add(a)

            # create bloom filter
            f, h = create_bloom_filter(20_000, 1 / 5_000_000, max_bit_size=0)
            for a in block_addresses:
                insert_to_bloom_filter(f, a, h)


            positive = 0
            t = time.time()
            for a in addresses:
                if contains_in_bloom_filter(f, a, h):
                    positive += 1
            t = time.time() - t
            q += t
            print("Block", i, "false positive", positive, "filter size", len(f), "time", t)
            if positive:
                blocks_affected += 1
        print("False positive blocks", blocks_affected, "from 2000", "time", q)

        print("Test false negative:")
        negative = 0
        for a in addresses:
            if not contains_in_bloom_filter(f, a, h):
                negative += 1
        print("False negative ", negative)
        print("Filter bytes per address ", len(f) / 20_000)

    def test_5_byte_hash_20000_1000000(self):
        return
        print("Hash 5 bytes as filter 20 000 elements vs 1 000 000 monitoring addresses:")

        print("generate address set ...")
        addresses = set()
        while len(addresses) < 1_000_000:
            addresses.add(sha256(int_to_bytes(random.randint(1, 0xFFFFFFFFFFFFFFFFFFFF)))[:21])

        haddresses = set()
        for a in addresses:
            haddresses.add(bytes_to_int(a[:5]))


        print("Test false positive rate for 2000 blocks:")

        blocks_affected = 0
        q = 0
        for i in range(2000):

            block_addresses = set()
            while len(block_addresses) < 20_000:
                a = sha256(int_to_bytes(random.randint(1, 0xFFFFFFFFFFFFFFFFFFFF)))[:21]
                if a in addresses:
                    continue
                block_addresses.add(bytes_to_int(a[:5]))

            # create gcs
            f = create_gcs(list(block_addresses), hashed=1, P=25, hex=0)


            positive = 0
            t = time.time()
            for a in block_addresses:
                if a in haddresses:
                    positive += 1
            t = time.time() - t
            q += t
            print("Block", i, "false positive", positive, "filter size", len(f), "time", t)
            if positive:
                blocks_affected += 1
        print("False positive blocks", blocks_affected, "from 2000", "time", q)

    def test_4_byte_hash_10000_100000(self):
        return
        print("Hash 4 bytes as filter 10 000 elements vs 100 000 monitoring addresses:")

        print("generate address set ...")
        addresses = set()
        while len(addresses) < 100_000:
            addresses.add(sha256(int_to_bytes(random.randint(1, 0xFFFFFFFFFFFFFFFFFFFF)))[:21])

        haddresses = set()
        for a in addresses:
            haddresses.add(bytes_to_int(a[:4]))


        print("Test false positive rate for 2000 blocks:")

        blocks_affected = 0
        q = 0
        for i in range(2000):

            block_addresses = set()
            while len(block_addresses) < 10_000:
                a = sha256(int_to_bytes(random.randint(1, 0xFFFFFFFFFFFFFFFFFFFF)))[:21]
                if a in addresses:
                    continue
                block_addresses.add(bytes_to_int(a[:4]))

            # create gcs
            f = create_gcs(list(block_addresses), hashed=1, P=18, hex=0)


            positive = 0
            t = time.time()
            for a in block_addresses:
                if a in haddresses:
                    positive += 1
            t = time.time() - t
            q += t
            print("Block", i, "false positive", positive, "filter size", len(f), "time", t)
            if positive:
                blocks_affected += 1
        print("False positive blocks", blocks_affected, "from 2000", "time", q)

    def test_bip58(self):
        return
        print("bip58 10 000 elements vs 784 931 monitoring addresses:")

        print("generate address set ...")
        addresses = set()
        while len(addresses) < 784_931:
            addresses.add(sha256(int_to_bytes(random.randint(1, 0xFFFFFFFFFFFFFFFFFFFF)))[:21])

        haddresses = set()
        for a in addresses:
            haddresses.add(map_into_range(siphash(a), 10000 * 784931))


        print("Test false positive rate for 2000 blocks:")

        blocks_affected = 0
        q = 0
        for i in range(2000):

            block_addresses = set()
            lblock_addresses = list()
            while len(block_addresses) < 10_000:
                a = sha256(int_to_bytes(random.randint(1, 0xFFFFFFFFFFFFFFFFFFFF)))[:21]
                if a in addresses:
                    continue
                block_addresses.add(map_into_range(siphash(a), 10000 * 784931))
                lblock_addresses.append(a)

            # create gcs
            f = create_gcs(lblock_addresses, hex=0)


            positive = 0
            t = time.time()
            for a in block_addresses:
                if a in haddresses:
                    positive += 1
            t = time.time() - t
            q += t
            print("Block", i, "false positive", positive, "filter size", len(f), "time", t)
            if positive:
                blocks_affected += 1
        print("False positive blocks", blocks_affected, "from 2000", "time", q)
        d = 2000 * len(f) + 1024 * 1024 * 1024 * blocks_affected
        d2 = 1024 * 1024 * 1024 * 2000
        print("Download", round(d /( 1024 * 1024 * 1024), 2),
              "Mb  vs ",  round(d2 /( 1024 * 1024 * 1024), 2),
              "Mb;  effectivity ", round( (1 - (d / d2)) * 100, 2) , " %")
        print("Filters size: ", round( (2000 * len(f) )/( 1024 * 1024 * 1024), 2), "Mb")



    def test_bip58_100000(self):
        return
        print("bip58 10 000 elements vs 100_000 monitoring addresses:")

        print("generate address set ...")
        addresses = set()
        while len(addresses) < 100_000:
            addresses.add(sha256(int_to_bytes(random.randint(1, 0xFFFFFFFFFFFFFFFFFFFF)))[:21])

        haddresses = set()
        for a in addresses:
            haddresses.add(map_into_range(siphash(a), 10000 * 784931))


        print("Test false positive rate for 2000 blocks:")

        blocks_affected = 0
        q = 0
        for i in range(2000):

            block_addresses = set()
            lblock_addresses = list()
            while len(block_addresses) < 10_000:
                a = sha256(int_to_bytes(random.randint(1, 0xFFFFFFFFFFFFFFFFFFFF)))[:21]
                if a in addresses:
                    continue
                block_addresses.add(map_into_range(siphash(a), 10000 * 784931))
                lblock_addresses.append(a)

            # create gcs
            f = create_gcs(lblock_addresses, hex=0)


            positive = 0
            t = time.time()
            for a in block_addresses:
                if a in haddresses:
                    positive += 1
            t = time.time() - t
            q += t
            print("Block", i, "false positive", positive, "filter size", len(f), "time", t)
            if positive:
                blocks_affected += 1
        print("False positive blocks", blocks_affected, "from 2000", "time", q)
        d = 2000 * len(f) + 1024 * 1024 * 1024 * blocks_affected
        d2 = 1024 * 1024 * 1024 * 2000
        print("Download", round(d /( 1024 * 1024 * 1024), 2),
              "Mb  vs ",  round(d2 /( 1024 * 1024 * 1024), 2),
              "Mb;  effectivity ", round( (1 - (d / d2)) * 100, 2) , " %")
        print("Filters size: ", round( (2000 * len(f) )/( 1024 * 1024 * 1024), 2), "Mb")



    def test_bip58_x100000(self):
        return
        print("bip58 10 000 elements vs 100_000 monitoring addresses:")

        print("generate address set ...")
        addresses = set()
        while len(addresses) < 100_000:
            addresses.add(sha256(int_to_bytes(random.randint(1, 0xFFFFFFFFFFFFFFFFFFFF)))[:21])

        haddresses = set()
        for a in addresses:
            haddresses.add(map_into_range(siphash(a), 10000 * 400031))


        print("Test false positive rate for 2000 blocks:")

        blocks_affected = 0
        q = 0
        for i in range(2000):

            block_addresses = set()
            lblock_addresses = list()
            while len(block_addresses) < 10_000:
                a = sha256(int_to_bytes(random.randint(1, 0xFFFFFFFFFFFFFFFFFFFF)))[:21]
                if a in addresses:
                    continue
                block_addresses.add(map_into_range(siphash(a), 10000 * 400031))
                lblock_addresses.append(a)

            # create gcs
            f = create_gcs(lblock_addresses, M=400031, P=18 ,hex=0)


            positive = 0
            t = time.time()
            for a in block_addresses:
                if a in haddresses:
                    positive += 1
            t = time.time() - t
            q += t
            print("Block", i, "false positive", positive, "filter size", len(f), "time", t)
            if positive:
                blocks_affected += 1
        print("False positive blocks", blocks_affected, "from 2000", "time", q)



    def test_gcs_20000_1000000(self):
        return
        print("\nGCS 20 000 elements vs 1 000 000 monitoring addresses:")

        print("generate address set ...")
        addresses = set()
        while len(addresses) < 1_000_000:
            addresses.add(sha256(int_to_bytes(random.randint(1, 0xFFFFFFFFFFFFFFFFFFFF)))[:21])

        haddresses = set()
        for a in addresses:
            haddresses.add(map_into_range(siphash(a), 10000 * 54975581))


        print("Test false positive rate for 2000 blocks:")

        blocks_affected = 0
        q = 0
        for i in range(2000):

            block_addresses = set()
            lblock_addresses = list()
            while len(block_addresses) < 10_000:
                a = sha256(int_to_bytes(random.randint(1, 0xFFFFFFFFFFFFFFFFFFFF)))[:21]
                if a in addresses:
                    continue
                block_addresses.add(map_into_range(siphash(a), 20000 * 54975581))
                lblock_addresses.append(a)

            # create gcs
            f = create_gcs(lblock_addresses, M=54975581, P=25 ,hex=0)


            positive = 0
            t = time.time()
            for a in block_addresses:
                if a in haddresses:
                    positive += 1
            t = time.time() - t
            q += t
            print("Block", i, "false positive", positive, "filter size", len(f), "time", t)
            if positive:
                blocks_affected += 1
        print("False positive blocks", blocks_affected, "from 2000", "time", q)
        d = 2000 * len(f) + 1024 * 1024 * 1024 * blocks_affected
        d2 = 1024 * 1024 * 1024 * 2000
        print("Download", round(d /( 1024 * 1024 * 1024), 2),
              "Mb  vs ",  round(d2 /( 1024 * 1024 * 1024), 2),
              "Mb;  effectivity ", round( (1 - (d / d2)) * 100, 2) , " %")
        print("Filters size: ", round( (2000 * len(f) )/( 1024 * 1024 * 1024), 2), "Mb")









    def test_bloom(self):
        return
        M = 1000000

        # f, h = create_bloom_filter(1, 1/784931, max_bit_size=0)
        # insert_to_bloom_filter(f, sha256(int_to_bytes(random.randint(1, 10000000000)))[:21], h)
        # print("len bloom ", len(f), f)
        k = set()
        while len(k) <= 10_000:
            k.add(sha256(int_to_bytes(random.randint(1, 10000000000)))[:21])
        # t = list()
        # for elem in k:
        #     t.append(bytes_to_int(sha256(int_to_bytes(random.randint(1, 10000000000)))[:3]))
        # # t = [bytes_to_int(i) for i in split_len(f,4)]
        # print("count chunks from bloom ",  len(t))
        # for i in range(15,20):
        #     g = create_gcs(t, hashed=1, P= i, hex=0)
        #     print(i, "length compressed bloom ",len(g))
        # t2 = decode_gcs(g,len(t), P=65)
        #
        # assert len(t) == len(t2)
        # for w in t:
        #     assert w in t2
        for i in range(20, 40):
            elements = set([bytes_to_int(e[:5])  for e in k])
            ll = create_gcs(list(elements), hashed=1, P=i , hex=0)
            print(i, "gcs len", len(ll))

        ll = create_gcs(list(k), hashed=0, hex=0)
        print("gcs len", len(ll))

        ll = create_gcs(list(k), hashed=0,M=4_753_997, P=22, hex=0)
        print("gcs len", len(ll))

        ll = create_gcs(list(k), hashed=0,M=4_753_997, P=23, hex=0)
        print("gcs len", len(ll))

        k2 = set()
        while len(k2) <= 1_000_000:
            i = sha256(int_to_bytes(random.randint(1, 10000000000)))[:21]
            if i not in k:
                k2.add(i)

        for ee in range(0):
            elements = set([map_into_range(siphash(e, v_0=ee), 10000 * 784931) for e in k])
            # elements = set([e[:5] for e in k])


            exist = 0
            a = set([map_into_range(siphash(e, v_0=ee), 10000 * 784931) for e in k2])
            # a = set([e[:5] for e in k2])
            for i in a:
                if i in elements:
                    exist += 1
            print(ee, "errors", exist)


        p = set()
        for i in k:
            f = bytearray(5)
            insert_to_bloom_filter(f, i, 23)
            p.add(bytes_to_int(f))

        print("len p", len(p))

        k2 = set()
        k3 = set()
        while len(k2) <= 1_000_000:
            i = sha256(int_to_bytes(random.randint(1, 1000000000000)))[:21]
            if i not in k:
                f = bytearray(5)
                insert_to_bloom_filter(f, i, 23)
                k2.add(bytes(f))
                k3.add(i)
        c = 0
        for ee in range(144):
            # elements = set([map_into_range(siphash(e, v_0=ee), 10000 * 784931) for e in k])
            p = set()
            while len(p) <= 1_0_000:
                f = bytearray(5)
                i = sha256(int_to_bytes(random.randint(1, 1000000000000)))[:21]
                if i in k3:
                    continue
                insert_to_bloom_filter(f, i, 23)
                p.add(bytes(f))

            exist = 0
            # a = set([map_into_range(siphash(e), 10000 * 784931) for e in k2])
            for i in p:
                if i in k2:
                    exist += 1
            print(ee, "errors", exist)
            if exist:
                c+=1
        print(c, "from ", 144)

        print("-----------------")
        c = 0
        k3 = set()
        k2 = set()
        while len(k2) <= 1_000_000:
            i = sha256(int_to_bytes(random.randint(1, 1000000000000)))[:21]
            if i not in k:
                k2.add(i[:5])
                k3.add(i)

        for ee in range(1440):
            p = set()
            while len(p) <= 1_0_000:
                i = sha256(int_to_bytes(random.randint(1, 1000000000000)))[:21]
                if i not in k3:
                    p.add(i[:5])


            exist = 0
            # a = set([map_into_range(siphash(e), 10000 * 784931) for e in k2])
            for i in p:
                if i in k2:
                    exist += 1
            print(ee, "errors", exist)
            if exist:
                c+=1
        print(c, "from ", 1440)

        return
        exist = 0
        for elem in k:
            if not contains_in_bloom_filter(f, elem, h):
                exist += 1
        print("errors", exist, len(k), len(lzma.compress(f)))

        p = set()
        c = 0
        print("filter len", len(f))
        return

        for i in range(144):
            p = set()
            while len(p)< 10000000:
                t = sha256(int_to_bytes(random.randint(1, 10000000000)))[:21]
                if t not in k:
                    p.add(t)

            exist = 0
            checked = 0
            for elem in p:
                if contains_in_bloom_filter(f, elem, h):
                    exist += 1
                checked += 1
            if exist:
                c += 1
            print(i, "errors", exist, len(p))

        print(c, "from", 144)

    def test_gcs(self):
        return
        print("Test gcs filter:")
        v_0, v_1 = hash_to_random_vectors("000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943")
        k = create_gcs(["4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35"
                        "504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac"], v_0=v_0, v_1=v_1, hex=1)
        self.assertEqual(k, "9dfca8")


        v_0, v_1 = hash_to_random_vectors("000000000000015d6077a411a8f5cc95caf775ccf11c54e27df75ce58d187313")
        k = create_gcs(["76a914876fbb82ec05caa6af7a3b5e5a983aae6c6cc6d688ac",
                        "76a9143ebc40e411ed3c76f86711507ab952300890397288ac",
                        "a914feb8a29635c56d9cd913122f90678756bf23887687",
                        "76a91450333046115eaa0ac9e0216565f945070e44573988ac",
                        "76a914c01a7ca16b47be50cbdbc60724f701d52d75156688ac",
                        "a914b7e6f7ff8658b2d1fb107e3d7be7af4742e6b1b387",
                        "76a914913bcc2be49cb534c20474c4dee1e9c4c317e7eb88ac",
                        "52534b424c4f434b3acd16772ad61a3c5f00287480b720f6035d5e54c9efc71be94bb5e3727f109090",
                        "a9148fc37ad460fdfbd2b44fe446f6e3071a4f64faa687"], v_0=v_0, v_1=v_1, hex=1)
        self.assertEqual(k, "027acea61b6cc3fb33f5d52f7d088a6b2f75d234e89ca800")
        # print("decoded >",decode_gcs(bytes_from_hex(k),9))

        # k = set()
        # while len(k) <= 10000:
        #     k.add(sha256(int_to_bytes(random.randint(1, 10000000000)))[:21])
        #
        # k = create_gcs(k, v_0=v_0, v_1=v_1)
        # print(len(k))

        # ll = sha256(int_to_bytes(random.randint(1, 10000000000)))[:21]
        # r = siphash(0x0706050403020100, 0x0F0E0D0C0B0A0908, ll)
        # print(hex(r))
        # c = 0
        # for i in range(144):
        #     p = set()
        #     while len(p)< 1000_000:
        #         t = sha256(int_to_bytes(random.randint(1, 10000000000)))[:21]
        #         if t != ll:
        #             p.add(t)
        #
        #     exist = 0
        #     checked = 0
        #     for elem in p:
        #         if siphash(0x0706050403020100,
        #                    0x0F0E0D0C0B0A0908,
        #                    elem) == r:
        #             exist += 1
        #         checked += 1
        #     print(i, "errors", exist, len(p))
        #     if exist:
        #         c += 1
        # print(c, "from", 144)


    def test_hash_to_random_vectors(self):
        print("\nTesting hash_to_random_vectors:")
        self.assertEqual(hash_to_random_vectors("000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"),
                         (8184490748024932675, 12593136414723666952))
        print("OK")

    def test_test(self):
        return
        r = sha256(int_to_bytes(random.randint(1, 100000000)))[:20]

        c = 0
        rr = r[:3]
        for i in range(144):
            p = set()
            while len(p)< 10_000_000:
                t = sha256(int_to_bytes(random.randint(1, 100000000)))[:20]
                if t != r:
                    p.add(t)

            exist = 0
            checked = 0
            for elem in p:
                if elem[:3] == rr:
                    exist += 1
                checked += 1
            print(i, ">errors", exist, len(p))
            if exist:
                c += 1
        print(c, "from", 144)


"""
bip158 - 10_000 x 784_931 :   size: 26312  effectivity  35.1 %
bip158 - 10_000 x 100_000 :   size: 26312  effectivity  88.2 %

GCS N=10000 M=54975581 P=25 - 10_000 x 1_000_000: size: 33990  effectivity  99.5 %


GCS N=20000 M=54975581 P=25 - 20_000 x 1_000_000: size: 67977  effectivity  98.34 %
GCS N=20000 M=54975581 P=25 - 20_000 x 10_000_000: size: 67977  effectivity  81.34 %
GCS N=20000 M=54975581 P=25 - 20_000 x 100_000_000: size: 67977  effectivity  16.84 %





"""