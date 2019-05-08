from pybtc import int_to_c_int, c_int_to_int, c_int_len
import asyncio
from collections import OrderedDict
from lru import LRU


class UTXO():
    def __init__(self, db_pool, loop, log, cache_size):
        self.cached = LRU(cache_size)
        self.missed = set()
        self.destroyed = LRU(200000)
        self.deleted = LRU(200000)
        self.log = log
        self.loaded = OrderedDict()
        self.maturity = 100
        self._cache_size = cache_size
        self._db_pool = db_pool
        self.loop = loop
        self.clear_tail = False
        self.last_saved_block = 0
        self.last_cached_block = 0
        self.save_process = False
        self.load_utxo_future = asyncio.Future()
        self.load_utxo_future.set_result(True)
        self._requests = 0
        self._failed_requests = 0
        self._hit = 0
        self.saved_utxo = 0
        self.deleted_utxo = 0
        self.deleted_utxo_saved = 0
        self.loaded_utxo = 0
        self.destroyed_utxo = 0
        self.destroyed_utxo_block = 0
        self.outs_total = 0

    def set(self, outpoint, pointer, amount, address):
        self.cached[outpoint] = (pointer, amount, address)
        self.outs_total += 1
        if pointer:
            self.last_cached_block = pointer >> 42

    def remove(self, outpoint):
        del self.cached[outpoint]

    def destroy_utxo(self, block_height):
        block_height -= self.maturity
        for key in range(self.destroyed_utxo_block + 1, block_height + 1):
            if key not in self.destroyed: continue
            n = set()
            for outpoint in self.destroyed[key]:
                try:
                    del self.cached[outpoint]
                    self.destroyed_utxo += 1
                except:
                    try:
                        del self.loaded[outpoint]
                        self.destroyed_utxo += 1
                        n.add(outpoint)
                    except:
                        self.destroyed_utxo += 1
                        pass
            self.deleted[key] = n
            del self.destroyed[key]

        self.destroyed_utxo_block = block_height
        if len(self.cached) - self._cache_size > 0 and not self.save_process:
            self.loop.create_task(self.save_utxo(block_height))

    async def save_utxo(self, block_height):
        # save to db tail from cache
        self.save_process = True
        await asyncio.sleep(2)
        c = len(self.cached) - self._cache_size
        try:
            lb = 0
            for key in iter(self.cached):
                i = self.cached[key]
                if c>0 and (i[0] >> 42) <= block_height:
                    c -= 1
                    lb = i[0] >> 42
                    continue
                break

            if lb:
                d = set()
                for key in range(self.last_saved_block + 1, lb + 1):
                    try:
                        [d.add(i) for i in self.deleted[key]]
                    except:
                        pass

                a = set()
                for key in iter(self.cached):
                    i = self.cached[key]
                    if (i[0] >> 42) > lb: break
                    a.add((key,b"".join((int_to_c_int(i[0]),
                                          int_to_c_int(i[1]),
                                          i[2]))))

                # insert to db
                async with self._db_pool.acquire() as conn:
                    async with conn.transaction():
                        if d:
                            await conn.execute("DELETE FROM connector_utxo WHERE "
                                               "outpoint = ANY($1);", d)
                        if a:
                            await conn.copy_records_to_table('connector_utxo',
                                                             columns=["outpoint", "data"], records=a)
                        await conn.execute("UPDATE connector_utxo_state SET value = $1 "
                                           "WHERE name = 'last_block';", lb)
                        await conn.execute("UPDATE connector_utxo_state SET value = $1 "
                                           "WHERE name = 'last_cached_block';", block_height)
                self.saved_utxo += len(a)
                self.deleted_utxo += len(d)

                # remove from cache
                for key in a:
                    try:
                        self.cached.pop(key[0])
                    except:
                        pass

                for key in range(self.last_saved_block + 1, lb + 1):
                    try:
                        self.deleted.pop(key)
                    except:
                        pass
                self.last_saved_block = lb
        finally:
            self.save_process = False

    def get(self, key, block_height):
        self._requests += 1
        try:
            i = self.cached[key]
            try:
                self.destroyed[block_height].add(key)
            except:
                self.destroyed[block_height] = {key}
            self._hit += 1
            return i
        except:
            self._failed_requests += 1
            self.missed.add(key)
            return None

    def get_loaded(self, key, block_height):
        try:
            i = self.loaded[key]
            try:
                self.destroyed[block_height].add(key)
            except:
                self.destroyed[block_height] = {key}
            return i
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
            async with self._db_pool.acquire() as conn:
                rows = await conn.fetch("SELECT outpoint, connector_utxo.data "
                                        "FROM connector_utxo "
                                        "WHERE outpoint = ANY($1);", l)
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

