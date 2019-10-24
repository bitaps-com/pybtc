import unittest
import os, sys
parentPath = os.path.abspath("..")
if parentPath not in sys.path:
    sys.path.insert(0, parentPath)
from pybtc import *
import random


def split_len(seq, length):
    return [seq[i:i+length] for i in range(0, len(seq), length)]


class filters(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("\nTesting filter functions:\n")


    def test_hash_to_random_vectors(self):
        print("\nTesting hash_to_random_vectors:")
        self.assertEqual(hash_to_random_vectors("000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"),
                         (8184490748024932675, 12593136414723666952))
        print("OK")

    def test_gcs(self):
        print("\nTest Golomb coded set filter:")
        v_0, v_1 = hash_to_random_vectors("000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943")
        k = create_gcs_filter(["4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35"
                        "504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac"], v_0=v_0, v_1=v_1, hex=1)
        self.assertEqual(k, "9dfca8")


        v_0, v_1 = hash_to_random_vectors("000000000000015d6077a411a8f5cc95caf775ccf11c54e27df75ce58d187313")
        k = create_gcs_filter(["76a914876fbb82ec05caa6af7a3b5e5a983aae6c6cc6d688ac",
                        "76a9143ebc40e411ed3c76f86711507ab952300890397288ac",
                        "a914feb8a29635c56d9cd913122f90678756bf23887687",
                        "76a91450333046115eaa0ac9e0216565f945070e44573988ac",
                        "76a914c01a7ca16b47be50cbdbc60724f701d52d75156688ac",
                        "a914b7e6f7ff8658b2d1fb107e3d7be7af4742e6b1b387",
                        "76a914913bcc2be49cb534c20474c4dee1e9c4c317e7eb88ac",
                        "52534b424c4f434b3acd16772ad61a3c5f00287480b720f6035d5e54c9efc71be94bb5e3727f109090",
                        "a9148fc37ad460fdfbd2b44fe446f6e3071a4f64faa687"], v_0=v_0, v_1=v_1, hex=1)
        self.assertEqual(k, "027acea61b6cc3fb33f5d52f7d088a6b2f75d234e89ca800")
        print("OK")

    def test_dhs(self):
        print("\nTesting Delta-Hoffman coded set")

        N=10000
        M=784931

        m_addresses = set()
        addresses = set()
        while len(m_addresses) <   N:
            a = sha256(int_to_bytes(random.randint(1, 0xFFFFFFFFFFFFFFFFFFFF)))[:21]
            if a in addresses:
                continue
            addresses.add(a)
            i = map_into_range(siphash(a),N*M)
            m_addresses.add(i)


        enocded_set = encode_dhcs(m_addresses)
        decoded_set = decode_dhcs(enocded_set)
        for i in m_addresses:
            self.assertEqual(i in decoded_set, 1)
        print("OK")

    def test_dhcs_vs_gcs(self):
        print("\nTest Delta-Hoffman vs Golomb")

        N=1000000
        M=784931
        m_addresses = set()
        addresses = set()
        while len(m_addresses) <   N:
            a = sha256(int_to_bytes(random.randint(1, 0xFFFFFFFFFFFFFFFFFFFF)))[:21]
            if a in addresses:
                continue
            addresses.add(a)
            i = map_into_range(siphash(a),N*M)
            m_addresses.add(i)
        print("addresses set created ", len(m_addresses))


        enocded_dhcs = encode_dhcs(m_addresses)
        enocded_gcs = encode_gcs(m_addresses, P=19)

        print("Delta-Hoffman  ",  round(len(enocded_dhcs)/1024/1024, 2), "Mb")
        print("Golomb  ",  round(len(enocded_gcs)/1024/1024, 2), "Mb")
        print("Delta-Hoffman redundancy ", round((len(enocded_dhcs)/len(enocded_gcs) - 1) * 100, 2), "%")
        print("OK")


    def test_bloom_filter(self):
        print("\n Test Bloom filter:")

        addresses = set()
        while len(addresses) < 20000:
            addresses.add(sha256(int_to_bytes(random.randint(1, 0xFFFFFFFFFFFFFFFFFFFF)))[:21])

        f, h = create_bloom_filter(20000, 1 / 1_000_000, max_bit_size=0)
        for a in addresses:
            insert_to_bloom_filter(f, a, h)
        for a in addresses:
            self.assertEqual(contains_in_bloom_filter(f, a, h), 1)
        print("OK")

    def test_bip58_simulation(self):

        print("bip58 10 000 monitoring addresses; 7300 elements; fpr 1/784931:")

        print("generate address set ...")
        addresses = set()
        while len(addresses) < 500:
            addresses.add(sha256(int_to_bytes(random.randint(1, 0xFFFFFFFFFFFFFFFFFFFF)))[:6])

        haddresses = set()
        for a in addresses:
            haddresses.add(map_into_range(siphash(a), 10000 * 100471170))

        haddresses = set()
        for a in addresses:
            haddresses.add(map_into_range(siphash(a), 500 * 784931))

        M = 784931
        P = 19
        c = encode_gcs(haddresses)
        print(len(c))
        c = encode_gcs(haddresses, P=19)
        print(len(c))
        return


        print("Test false positive rate for 2739 ( 20 000 000 items) blocks:")

        blocks_affected = 0
        q = 0
        for i in range(2000):

            block_addresses = set()
            lblock_addresses = list()
            while len(block_addresses) < 7300:
                a = sha256(int_to_bytes(random.randint(1, 0xFFFFFFFFFFFFFFFFFFFF)))[:21]
                if a in addresses:
                    continue
                block_addresses.add(map_into_range(siphash(a), 7300 * 100471170))
                lblock_addresses.append(a)

            # create gcs
            f = create_gcs_filter(lblock_addresses, hex=0)


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
        d = 2000 * len(f) + 1024 * 1024  * blocks_affected
        d2 = 1024 * 1024  * 2000
        print("Download", round(d /1024 / 1024 , 2),
              "Mb  vs ",  round(d2 /( 1024 * 1024 ), 2),
              "Mb;  effectivity ", round( (1 - (d / d2)) * 100, 2) , " %")
        print("Filters size: ", round( (2000 * len(f) )/( 1024 * 1024 ), 2), "Mb")

        return
        print("Test false positive rate for 684 ( 5 000 000 items) blocks:")
        blocks_affected = 0
        q = 0
        for i in range(684):

            block_addresses = set()
            lblock_addresses = list()
            while len(block_addresses) < 7300:
                a = sha256(int_to_bytes(random.randint(1, 0xFFFFFFFFFFFFFFFFFFFF)))[:21]
                if a in addresses:
                    continue
                block_addresses.add(map_into_range(siphash(a), 7300 * 784931))
                lblock_addresses.append(a)

            # create gcs
            f = create_gcs_filter(lblock_addresses, hex=0)


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
        d = 2000 * len(f) + 1024 * 1024  * blocks_affected
        d2 = 1024 * 1024  * 2000
        print("Download", round(d /1024 / 1024 , 2),
              "Mb  vs ",  round(d2 /( 1024 * 1024 ), 2),
              "Mb;  effectivity ", round( (1 - (d / d2)) * 100, 2) , " %")
        print("Filters size: ", round( (2000 * len(f) )/( 1024 * 1024 * 1024), 2), "Mb")


    def test_dhcs_simulation(self):
        return
        print("--:")

        print("generate address set ...")
        addresses = set()
        while len(addresses) < 10000:
            addresses.add(sha256(int_to_bytes(random.randint(1, 0xFFFFFFFFFFFFFFFFFFFF)))[:21])

        haddresses = set()
        for a in addresses:
            haddresses.add(map_into_range(siphash(a), 10000 * 1000000000))


        print("Test false positive rate for 35 ( 700 000 000 items) block batches:")

        blocks_affected = 0
        q = 0
        f = b""
        for i in range(2000):

            block_addresses = set()
            while len(block_addresses) < 7300:
                a = sha256(int_to_bytes(random.randint(1, 0xFFFFFFFFFFFFFFFFFFFF)))[:21]
                if a in addresses:
                    continue
                block_addresses.add(map_into_range(siphash(a), 10000 * 1000000000))


            # create gcs
            if not f:
                f = encode_dhcs(block_addresses)



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
        d = 2000 * len(f) + 1024 * 1024  * blocks_affected
        d2 = 1024 * 1024  * 2000
        print("Download", round(d /1024 / 1024 , 2),
              "Mb  vs ",  round(d2 /( 1024 * 1024 ), 2), "Mb;")
        print("Filters size: ", round( (2000 * len(f) )/( 1024 * 1024), 2), "Mb")














    def test_bip1582(self):
        return
        print("\nTest bip158")

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

    def test_bip5833(self):
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










    def test_dhcs_simulationxx(self):
        return
        print("\nTest Delta-Hoffman simulation")

        N=7300
        M=784931

        m_addresses = set()
        addresses = set()
        while len(m_addresses) <   10000:
            a = sha256(int_to_bytes(random.randint(1, 0xFFFFFFFFFFFFFFFFFFFF)))[:21]
            if a in addresses:
                continue
            addresses.add(a)
            i = map_into_range(siphash(a),N*M)
            m_addresses.add(i)
        print("addresses set created ", len(m_addresses))


        enocded_dhcs = encode_dhcs(m_addresses)
        decoded_dhcs = decode_dhcs(enocded_dhcs)



        q2 = len(f2)
        print("filter len ", len(f2)/ 1024, len(zlib.compress(f2)) / 1024 )
        print(1 - q2/q1)
        return

        s = set(decode_gcs(f2, 20_000_000, P=19))

        for qq in range(35):
            k = 0
            m2_addresses = set()
            while len(m2_addresses) < 10_000:
                a = sha256(int_to_bytes(random.randint(1, 0xFFFFFFFFFFFFFFFFFFFF)))[:21]
                if a in addresses:
                    continue
                i = map_into_range(siphash(a), N * M)
                m2_addresses.add(i)

            for g in m2_addresses:
                if g in s:
                    k+= 1
            print(qq, k)
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



"""
bip158 - 10_000 x 784_931 :   size: 26312  effectivity  35.1 %
bip158 - 10_000 x 100_000 :   size: 26312  effectivity  88.2 %

GCS N=10000 M=54975581 P=25 - 10_000 x 1_000_000: size: 33990  effectivity  99.5 %


GCS N=20000 M=54975581 P=25 - 20_000 x 1_000_000: size: 67977  effectivity  98.34 %
GCS N=20000 M=54975581 P=25 - 20_000 x 10_000_000: size: 67977  effectivity  81.34 %
GCS N=20000 M=54975581 P=25 - 20_000 x 100_000_000: size: 67977  effectivity  16.84 %





"""