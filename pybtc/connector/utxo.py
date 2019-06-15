from pybtc import bytes_to_int, c_int_to_int, c_int_len
from pybtc import int_to_bytes, rh2s, parse_script
import asyncio
from collections import OrderedDict, deque
from pybtc  import MRU, LRU
import traceback
import time
import pickle

try: import rocksdb
except: pass
try: import plyvel
except: pass


class UTXO():
    def __init__(self, db_type, db,  rpc, loop, log, cache_size):
        self.cache = MRU()  # utxo cache
        self.restore_blocks_cache = LRU()  # utxo cache

        self.missed = deque()  # missed utxo
        self.missed_failed = deque()
        self.loaded = dict()   # loaded from db missed records

        self.utxo_records = deque()  # prepared utxo records for write to db
        self.pending_saved = dict()  # temp hash table, while records write process

        self.deleted = deque()  # scheduled to delete
        self.deleted_utxo = deque()

        self.destroyed = deque()

        self.checkpoint = 0
        self.checkpoints = list()
        self.log = log


        self.size_limit = cache_size
        self.db_type = db_type
        self.db = db
        self.loop = loop

        self.save_process = False
        self.write_to_db = False
        self.load_utxo_future = asyncio.Future()
        self.load_utxo_future.set_result(True)
        self.rpc = rpc

        # stats
        self._requests = 0
        self._failed_requests = 0
        self._hit = 0
        self.saved_utxo_count = 0

        self.last_block = 0
        self.deleted_utxo_count = 0
        self.read_from_db_time = 0
        self.read_from_db_batch_time = 0
        self.read_from_db_count = 0
        self.read_from_db_time_total = 0
        self.loaded_utxo_count = 0



    def set(self, outpoint, pointer, amount, address):
        self.cache[outpoint] = (pointer, amount, address)

    def remove(self, outpoint):
        del self.cache[outpoint]


    def create_checkpoint(self, app_last_block = None):
        # check checkpoints state
        if  not self.checkpoints: return
        checkpoints = set()
        for i in self.checkpoints:
            if i > self.checkpoint: checkpoints.add(i)
        self.checkpoints = sorted(checkpoints)
        # save to db tail from cache
        if  self.save_process or not self.cache: return
        if app_last_block is not None:
            if app_last_block < self.checkpoints[0]: return

        self.save_process = True
        limit = 0
        try:
            checkpoint = self.checkpoints.pop(0)
            lb = 0
            while self.cache:
                key, value = self.cache.peek_last_item()
                if value[0] >> 39 != lb:
                    # block changed

                    if checkpoint <= lb:
                        # last block was checkpoint block
                        if len(self.utxo_records) > self.size_limit * 0.9:
                            limit = self.size_limit
                        else:
                            limit = self.size_limit * 0.9

                        if len(self.cache) < limit:
                            break

                        if self.checkpoints:
                            if app_last_block is None:
                                # no app checkpoint constraint

                                checkpoint = self.checkpoints.pop(0)
                            elif app_last_block > self.checkpoints[0]:
                                # app checkpoint ahead of utxo checkpoint

                                checkpoint = self.checkpoints.pop(0)
                            else:
                                break
                        else:
                            # no more checkpoints
                            break

                lb = value[0] >> 39

                self.cache.delete(key)
                self.utxo_records.append((key, value[0], value[2], value[1]))
                self.pending_saved[key] = value
            self.last_checkpoint = self.checkpoint
            self.checkpoint = lb


            #  prepare records for destroyed coins in db
            while self.deleted:
                if self.deleted[0][0] <= lb:
                    self.deleted_utxo.append(self.deleted[0][1])
                    self.deleted.popleft()
                else:
                    break


            # if app_last_block:
            #     # prepare cache restore data
            #     while self.destroyed:
            #         if self.destroyed[0][1][0] >> 39 <= app_last_block:
            #             self.destroyed.popleft()
            #         else:
            #             break
            # else:
            #     self.destroyed = deque()
            # print(">>", len(self.destroyed), (self.destroyed[0][1][0] >> 39,
            #                                   app_last_block))
            # self.destroyed_backup = pickle.dumps(self.destroyed)

            self.log.debug("checkpoint %s cache size %s limit %s" % (self.checkpoint,
                                                                        len(self.cache),
                                                                        limit))
        except:
            self.log.critical("create checkpoint error")
            self.log.critical(str(traceback.format_exc()))

    def rocksdb_atomic_batch(self):
        batch = rocksdb.WriteBatch()
        [batch.delete(k) for k in self.deleted_utxo]
        [batch.put(k[0], k[1]) for k in self.utxo_records]
        batch.put(b"last_block", int_to_bytes(self.checkpoint))
        self.db.write(batch)

    def leveldb_atomic_batch(self):
        with self.db.write_batch() as batch:
            [batch.delete(k) for k in self.deleted_utxo]
            [batch.put(k[0], k[1]) for k in self.utxo_records]
            batch.put(b"last_block", int_to_bytes(self.checkpoint))


    async def postgresql_atomic_batch(self):
        async with self.db.acquire() as conn:
            async with conn.transaction():
               if self.deleted_utxo:
                   await conn.execute("DELETE FROM connector_utxo WHERE "
                                      "outpoint = ANY($1);", self.deleted_utxo)
               if self.utxo_records:
                   await conn.copy_records_to_table('connector_utxo',
                                                    columns=["outpoint",
                                                             "pointer",
                                                             "address",
                                                             "amount"],
                                                    records=self.utxo_records)
               await conn.execute("UPDATE connector_utxo_state SET value = $1 "
                                  "WHERE name = 'last_block';", int_to_bytes(self.checkpoint))
               await conn.execute("UPDATE connector_utxo_state SET value = $1 "
                                  "WHERE name = 'last_cached_block';", int_to_bytes(self.last_block))
               # await conn.execute("UPDATE connector_utxo_state SET value = $1 "
               #                    "WHERE name = 'cache_restore';", self.destroyed_backup)

    # async def restore_cache(self):
    #     async with self.db.acquire() as conn:
    #         row = await conn.fetchval("SELECT value FROM connector_utxo_state "
    #                                   "WHERE name = 'cache_restore' LIMIT 1")
    #     if row:
    #         self.deleted = pickle.loads(row["value"])
    #         for r in self.deleted:
    #             self.restored[r[0]] = r[1]


    async def save_checkpoint(self):
            # save to db tail from cache
            if  not self.checkpoint: return
            if  self.write_to_db: return
            try:
                self.write_to_db = True
                t = time.time()
                if not self.checkpoint: return
                if self.db_type == "rocksdb":
                    await self.loop.run_in_executor(None, self.rocksdb_atomic_batch)
                elif self.db_type == "leveldb":
                    await self.loop.run_in_executor(None, self.leveldb_atomic_batch)
                else:
                    await self.postgresql_atomic_batch()
                self.log.debug("utxo checkpoint saved time %s" % round(time.time()-t, 4))
                self.saved_utxo_count += len(self.utxo_records)
                self.deleted_utxo_count += len(self.deleted_utxo)
                self.deleted_utxo = deque()
                self.utxo_records = deque()
                self.pending_saved = dict()

            except Exception as err:
                self.log.critical("save_checkpoint error: %s" % str(err))
            finally:
                self.save_process = False
                self.write_to_db = False

    def get(self, key):
        self._requests += 1
        i = None
        try:
            i = self.cache.delete(key)
        except:
            try:
                i = self.pending_saved[key]
            except:
                pass
        if i is None:
            self._failed_requests += 1
            self.missed.append(key)
        else:
            self._hit += 1
            # self.destroyed.append((key, i))
        return i

    # async def get_from_daemon(self, key):
    #     try:
    #         tx_id = rh2s(key[:32])
    #         out_index = bytes_to_int(key[32:])
    #         tx = await self.rpc.getrawtransaction(tx_id, 1)
    #         amount = int(tx["vout"][out_index]["value"] * 100000000)
    #         script = parse_script(tx["vout"][out_index]["scriptPubKey"]["hex"])
    #         try:
    #             address = b"".join((bytes([script["nType"]]), script["addressHash"]))
    #         except:
    #             address = b"".join((bytes([script["nType"]]), script["scriptPubKey"]))
    #         try:
    #             block = self.restore_blocks_cache[tx["blockhash"]]
    #         except:
    #             block = await self.rpc.getblock(tx["blockhash"])
    #             self.restore_blocks_cache[tx["blockhash"]] = block
    #
    #         tx_index = block["tx"].index(tx_id)
    #         block_height  = block["height"]
    #         pointer = (block_height << 39) + (tx_index << 20) + (1 << 19) + out_index
    #         return (pointer, amount, address)
    #     except:
    #         print(traceback.format_exc())
    #         return None






    def get_loaded(self, key):
        try:
            i = self.loaded.pop(key)
            self.deleted.append((i[0]>>39, key))
            return i
        except:
            return None

    async def load_utxo_from_daemon(self):
        if not self.missed_failed: return
        result = await self.rpc.batch([["getrawtransaction", rh2s(i[:32]), 1] for i in self.missed_failed])
        hash_list = set()
        for r in result:
            if r["result"]["blockhash"] not in self.restore_blocks_cache:
                hash_list.add(r["result"]["blockhash"])

        result2 = await self.rpc.batch([["getblock", r] for r in hash_list])
        for r in result2:
           self.restore_blocks_cache[r["result"]["hash"]] = r["result"]

        for key, r in zip(self.missed_failed, result):
            out_index = bytes_to_int(key[32:])
            tx=r["result"]
            amount = int(tx["vout"][out_index]["value"] * 100000000)
            script = parse_script(tx["vout"][out_index]["scriptPubKey"]["hex"])
            try:
                address = b"".join((bytes([script["nType"]]), script["addressHash"]))
            except:
                address = b"".join((bytes([script["nType"]]), script["scriptPubKey"]))
            block = self.restore_blocks_cache[tx["blockhash"]]

            tx_index = block["tx"].index(tx["txid"])
            block_height = block["height"]
            pointer = (block_height << 39) + (tx_index << 20) + (1 << 19) + out_index
            self.loaded[key] = (pointer, amount, address)

        while len(self.restore_blocks_cache) > 1000:
            self.restore_blocks_cache.pop()






    async def load_utxo(self):
        while True:
            if not self.load_utxo_future.done():
                await self.load_utxo_future
                continue
            break
        try:
            self.load_utxo_future = asyncio.Future()
            t = time.time()
            if self.db_type == "postgresql":
                async with self.db.acquire() as conn:
                    rows = await conn.fetch("SELECT outpoint, "
                                            "       pointer,"
                                            "       address,"
                                            "       amount "
                                            "FROM connector_utxo "
                                            "WHERE outpoint = ANY($1);", self.missed)
                for row in rows:
                    self.loaded[row["outpoint"]] = (row["pointer"],
                                                    row["amount"],
                                                    row["address"])
                    self.loaded_utxo_count += 1

                if len(self.missed) > len(rows):
                    self.missed_failed = set(self.missed)
                    for row in rows:
                        if row["outpoint"] not in self.missed:
                            self.missed.remove(row["outpoint"])
                    self.missed_failed = list(self.missed)


            elif self.db_type == "rocksdb":
                rows = self.db.multi_get(list(self.missed))
                for outpoint in rows:
                    d = rows[outpoint]
                    pointer = c_int_to_int(d)
                    f = c_int_len(pointer)
                    amount = c_int_to_int(d[f:])
                    f += c_int_len(amount)
                    address = d[f:]
                    self.loaded[outpoint] = (pointer, amount, address)
                    self.loaded_utxo_count += 1
            else:
                for outpoint in self.missed:
                    d = self.db.get(outpoint)
                    if d is None: continue
                    pointer = c_int_to_int(d)
                    f = c_int_len(pointer)
                    amount = c_int_to_int(d[f:])
                    f += c_int_len(amount)
                    address = d[f:]
                    self.loaded[outpoint] = (pointer, amount, address)
                    self.loaded_utxo_count += 1


            self.read_from_db_count += len(self.missed)
            self.read_from_db_time += time.time() - t
            self.read_from_db_batch_time += time.time() - t
            self.read_from_db_time_total += time.time() - t

            self.missed= deque()
        except:
            self.log.critical(str(traceback.format_exc()))
        finally:
            self.load_utxo_future.set_result(True)


    def len(self):
        return len(self.cache)

    def hit_rate(self):
        if self._requests:
            return self._hit / self._requests
        else:
            return 0

