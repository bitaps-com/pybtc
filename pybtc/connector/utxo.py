from pybtc import int_to_c_int, c_int_to_int, c_int_len
from pybtc import int_to_bytes, bytes_to_int
import asyncio
from collections import OrderedDict
from pybtc  import MRU
import traceback
import rocksdb

class UTXO():
    def __init__(self, db, loop, log, cache_size):
        self.cached = MRU()
        self.missed = set()
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
        self.deleted_utxo_saved = 0
        self.loaded_utxo = 0
        self.destroyed_utxo = 0
        self.destroyed_utxo_block = 0
        self.outs_total = 0

    def set(self, outpoint, pointer, amount, address):
        self.cached[outpoint] = (pointer, amount, address)

    def remove(self, outpoint):
        del self.cached[outpoint]


    def create_checkpoint(self):
        # save to db tail from cache
        if  self.save_process or not self.cached: return
        if  not self.checkpoints: return
        self.save_process = True
        try:
            i = self.cached.peek_last_item()
            self.checkpoints = sorted(self.checkpoints)
            checkpoint = self.checkpoints.pop(0)
            lb = 0
            block_changed = False
            checkpoint_found = False

            while self.cached:
                i = self.cached.pop()
                if lb != i[1][0] >> 42:
                    block_changed = True
                    lb = i[1][0] >> 42
                if lb - 1 == checkpoint:
                    if len(self.cached) > int(self.size_limit * 0.9):
                        if self.checkpoints:
                            checkpoint = self.checkpoints.pop(0)
                    else:
                        checkpoint_found = True
                while self.checkpoints and checkpoint < lb - 1:
                    checkpoint = self.checkpoints.pop(0)

                if len(self.cached) <= self.size_limit:
                    if block_changed and checkpoint_found:
                        break
                self.pending_utxo.add((i[0],b"".join((int_to_c_int(i[1][0]),
                                         int_to_c_int(i[1][1]),
                                         i[1][2]))))
                self.pending_saved[i[0]] = i[1]
            if block_changed:
                self.cached.append({i[0]: i[1]})
                lb -= 1

            self.checkpoint = lb  if checkpoint_found else None

        except:
            self.log.critical("create checkpoint error")
            self.log.critical(str(traceback.format_exc()))


    async def save_checkpoint(self):
        # save to db tail from cache
        if  not self.checkpoint: return
        if  self.write_to_db: return
        try:
            self.write_to_db = True
            if not self.checkpoint: return

            batch = rocksdb.WriteBatch()
            [batch.delete(k) for k in self.pending_deleted]
            for k in self.pending_utxo:
                batch.put(k[0], k[1])
            batch.put(b"last_block", int_to_bytes(self.checkpoint))
            batch.put(b"last_cached_block", int_to_bytes(self.deleted_last_block))
            self.db.write(batch)

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
                self.missed.add(key)
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
            l = set(self.missed)
            rows = []
            [rows.append({"outpoint": k, "data": self.db.get(k)}) for k in l]
            for i in l:
                try:
                    self.missed.remove(i)
                except:
                    pass
            for row in rows:
                d = row["data"]
                pointer = c_int_to_int(d)
                f = c_int_len(pointer)
                amount = c_int_to_int(d[f:])
                f += c_int_len(amount)
                address = d[f:]
                self.loaded[row["outpoint"]] = (pointer, amount, address)
                self.loaded_utxo += 1
        finally:
            self.load_utxo_future.set_result(True)


    def len(self):
        return len(self.cached)

    def hit_rate(self):
        if self._requests:
            return self._hit / self._requests
        else:
            return 0

