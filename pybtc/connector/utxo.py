from pybtc import int_to_c_int, c_int_to_int, c_int_len
from pybtc import int_to_bytes, bytes_to_int
import asyncio
from collections import OrderedDict, deque
from pybtc  import MRU
import traceback
import time

try: import rocksdb
except: pass
try: import plyvel
except: pass


class UTXO():
    def __init__(self, db_type, db,  loop, log, cache_size):
        self.cached = MRU()
        self.missed = deque()
        self.deleted = set()
        self.pending_deleted = set()
        self.pending_utxo = set()
        self.checkpoint = None
        self.checkpoints = list()
        self.log = log
        self.loaded = MRU()
        self.pending_saved = OrderedDict()
        self.maturity = 100
        self.size_limit = cache_size
        self.db_type = db_type
        self.db = db
        self.loop = loop
        self.clear_tail = False
        self.last_saved_block = 0
        self.last_cached_block = 0
        self.save_process = False
        self.write_to_db = False
        self.load_utxo_future = asyncio.Future()
        self.load_utxo_future.set_result(True)
        self._requests = 0
        self._failed_requests = 0
        self._hit = 0
        self.saved_utxo = 0
        self.deleted_utxo = 0
        self.deleted_last_block = 0
        self.deleted_utxo = 0
        self.read_from_db_time = 0
        self.read_from_db_batch_time = 0
        self.read_from_db_count = 0
        self.read_from_db_time_total = 0
        self.loaded_utxo = 0
        self.destroyed_utxo = 0
        self.destroyed_utxo_block = 0
        self.outs_total = 0

    def set(self, outpoint, pointer, amount, address):
        self.cached[outpoint] = (pointer, amount, address)

    def remove(self, outpoint):
        del self.cached[outpoint]


    def create_checkpoint(self, app_last_block = None):
        # save to db tail from cache
        self.log.critical("create utxo checkpoint")
        if app_last_block:
            self.log.critical("Application last block  %s;" % app_last_block)
        if self.checkpoints:
            self.log.critical("Available utxo checkpoint %s; first %s; last %s;" %
                              (len(self.checkpoints),
                               self.checkpoints[0],
                               self.checkpoints[-1]))
        if  self.save_process or not self.cached:
            self.log.critical("Create utxo checkpoint canceled %s" % str((self.save_process,
                                                                         len( self.cached))))
            return
        if  not self.checkpoints:
            self.log.critical("Create utxo checkpoint canceled: no checkoints")
            return
        if app_last_block is not None:
            if app_last_block < self.checkpoints[0]:
                self.log.critical("Create utxo checkpoint canceled - utxo lag")
                return

        self.save_process = True
        limit = 0
        try:
            checkpoint = self.checkpoints.pop(0)
            lb = 0
            while self.cached:
                key, value = self.cached.peek_last_item()
                if value[0] >> 39 != lb:
                    # block changed

                    if checkpoint == lb:
                        # last block was checkpoint block
                        if len(self.pending_utxo) > self.size_limit * 0.9:
                            limit = self.size_limit
                        else:
                            limit = self.size_limit * 0.9

                        if len(self.cached) < limit:
                            break

                        if self.checkpoints:
                            if app_last_block is None:
                                # no app checkpoint constraint
                                checkpoint = self.checkpoints.pop(0)
                            elif app_last_block > self.checkpoints[0]:
                                # app checkpoint ahead of utxo checkpoint

                                checkpoint = self.checkpoints.pop(0)
                                self.log.critical("pop checkpoint %s " % checkpoint)
                            else:
                                break
                        else:
                            # no more checkpoints
                            break

                    lb = value[0] >> 39

                self.cached.delete(key)
                self.pending_utxo.add((key, value[0], value[2], value[1]))
                self.pending_saved[key] = value


            self.checkpoint = lb
            self.log.critical("checkpoint %s cache size %s limit %s" % (self.checkpoint,
                                                                        len(self.cached),
                                                                        limit))
        except:
            self.log.critical("create checkpoint error")
            self.log.critical(str(traceback.format_exc()))

    def rocksdb_atomic_batch(self):
        batch = rocksdb.WriteBatch()
        [batch.delete(k) for k in self.pending_deleted]
        [batch.put(k[0], k[1]) for k in self.pending_utxo]
        batch.put(b"last_block", int_to_bytes(self.checkpoint))
        batch.put(b"last_cached_block", int_to_bytes(self.deleted_last_block))
        self.db.write(batch)

    def leveldb_atomic_batch(self):
        with self.db.write_batch() as batch:
            [batch.delete(k) for k in self.pending_deleted]
            [batch.put(k[0], k[1]) for k in self.pending_utxo]
            batch.put(b"last_block", int_to_bytes(self.checkpoint))
            batch.put(b"last_cached_block", int_to_bytes(self.deleted_last_block))


    async def postgresql_atomic_batch(self):
        async with self.db.acquire() as conn:
            async with conn.transaction():
               if self.pending_deleted:
                   await conn.execute("DELETE FROM connector_utxo WHERE "
                                      "outpoint = ANY($1);", self.pending_deleted)
               if self.pending_utxo:
                   await conn.copy_records_to_table('connector_utxo',
                                                    columns=["outpoint",
                                                             "pointer",
                                                             "address",
                                                             "amount"],
                                                    records=self.pending_utxo)
               await conn.execute("UPDATE connector_utxo_state SET value = $1 "
                                  "WHERE name = 'last_block';", self.checkpoint)
               await conn.execute("UPDATE connector_utxo_state SET value = $1 "
                                  "WHERE name = 'last_cached_block';", self.deleted_last_block)


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
                self.saved_utxo += len(self.pending_utxo)
                self.deleted_utxo += len(self.pending_deleted)
                self.pending_deleted = set()
                self.pending_utxo = set()
                self.pending_saved = OrderedDict()
                self.last_saved_block = self.checkpoint
                self.checkpoint = None
            except Exception as err:
                self.log.critical("save_checkpoint error: %s" % str(err))
            finally:
                self.save_process = False
                self.write_to_db = False

    def get(self, key):
        self._requests += 1
        try:
            i = self.cached.delete(key)
            self._hit += 1
            return i
        except:
            try:
                i = self.pending_saved[key]
                self._hit += 1
                return i
            except:
                self._failed_requests += 1
                self.missed.append(key)
                return None

    def get_loaded(self, key):
        try:
            self.deleted.add(key)
            return self.loaded.delete(key)
        except:
            return None


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
                    self.loaded_utxo += 1


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
                    self.loaded_utxo += 1
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
                    self.loaded_utxo += 1


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
        return len(self.cached)

    def hit_rate(self):
        if self._requests:
            return self._hit / self._requests
        else:
            return 0

