from pybtc.functions.tools import rh2s, s2rh
from pybtc.functions.tools import var_int_to_int
from pybtc.functions.tools import read_var_int
from pybtc.transaction import Transaction
from pybtc import int_to_c_int, c_int_to_int, c_int_len, int_to_bytes
import traceback
import aiojsonrpc
import zmq
import zmq.asyncio
import asyncio
import time
import io
from collections import OrderedDict

class Connector:
    def __init__(self, node_rpc_url, node_zerromq_url, logger,
                 last_block_height=0, chain_tail=None,
                 tx_handler=None, orphan_handler=None,
                 before_block_handler=None, block_handler=None, after_block_handler=None,
                 block_timeout=30,
                 deep_sync_limit=20, backlog=0, mempool_tx=True,
                 rpc_batch_limit=20, rpc_threads_limit=100, rpc_timeout=100,
                 preload=False,
                 utxo_data=False,
                 utxo_cache_size=2000000,
                 skip_opreturn=True,
                 postgres_pool=None):
        self.loop = asyncio.get_event_loop()

        # settings
        self.log = logger
        self.rpc_url = node_rpc_url
        self.zmq_url = node_zerromq_url
        self.orphan_handler = orphan_handler
        self.block_timeout = block_timeout
        self.tx_handler = tx_handler
        self.skip_opreturn = skip_opreturn
        self.before_block_handler = before_block_handler
        self.block_handler = block_handler
        self.after_block_handler = after_block_handler
        self.deep_sync_limit = deep_sync_limit
        self.backlog = backlog
        self.mempool_tx = mempool_tx
        self.postgress_pool = postgres_pool
        self.utxo_cache_size = utxo_cache_size
        self.utxo_data = utxo_data
        self.chain_tail = list(chain_tail) if chain_tail else []
        self.rpc_timeout = rpc_timeout
        self.batch_limit = rpc_batch_limit

        # state and stats
        self.node_last_block = None
        self.utxo = None
        self.cache_loading = False
        self.app_block_height_on_start = int(last_block_height) if int(last_block_height) else 0
        self.last_block_height = 0
        self.last_block_utxo_cached_height = 0
        self.deep_synchronization = False

        self.block_dependency_tx = 0 # counter of tx that have dependencies in block
        self.active = True
        self.get_next_block_mutex = asyncio.Future()
        self.get_next_block_mutex.set_result(True)
        self.active_block = asyncio.Future()
        self.active_block.set_result(True)
        self.last_zmq_msg = int(time.time())
        self.total_received_tx = 0
        self.blocks_processed_count = 0
        self.blocks_decode_time = 0
        self.blocks_download_time = 0
        self.total_received_tx_time = 0
        self.start_time = time.time()

        # cache and system
        self.preload = preload
        self.block_preload = Cache(max_size=50000)
        self.block_hashes_preload = Cache(max_size=50000)
        self.tx_cache = Cache(max_size=50000)
        self.block_cache = Cache(max_size=10000)

        self.block_txs_request = None

        self.connected = asyncio.Future()
        self.await_tx = list()
        self.missed_tx = list()
        self.await_tx_future = dict()
        self.add_tx_future = dict()
        self.get_missed_tx_threads = 0
        self.get_missed_tx_threads_limit = rpc_threads_limit
        self.tx_in_process = set()
        self.zmqContext = None
        self.tasks = list()
        self.log.info("Node connector started")
        asyncio.ensure_future(self.start(), loop=self.loop)

    async def start(self):
        await self.utxo_init()

        while True:
            self.log.info("Connector initialization")
            try:
                self.rpc = aiojsonrpc.rpc(self.rpc_url, self.loop, timeout=self.rpc_timeout)
                self.node_last_block = await self.rpc.getblockcount()
            except Exception as err:
                self.log.error("Get node best block error:" + str(err))
            if not isinstance(self.node_last_block, int):
                self.log.error("Get node best block height failed")
                self.log.error("Node rpc url: "+self.rpc_url)
                await asyncio.sleep(10)
                continue

            self.log.info("Node best block height %s" %self.node_last_block)
            self.log.info("Connector last block height %s" % self.last_block_height)

            if self.node_last_block < self.last_block_height:
                self.log.error("Node is behind application blockchain state!")
                await asyncio.sleep(10)
                continue
            elif self.node_last_block == self.last_block_height:
                self.log.warning("Blockchain is synchronized")
            else:
                d = self.node_last_block - self.last_block_height
                self.log.warning("%s blocks before synchronization synchronized" % d)
                if d > self.deep_sync_limit:
                    self.log.warning("Deep synchronization mode")
                    self.deep_synchronization = True
            break

        if self.utxo_data:
            self.utxo = UTXO(self.postgress_pool,
                             self.loop,
                             self.log,
                             self.utxo_cache_size if self.deep_synchronization else 0)

        h = self.last_block_height
        if h < len(self.chain_tail):
            raise Exception("Chain tail len not match last block height")
        for row in reversed(self.chain_tail):
            self.block_cache.set(row, h)
            h -= 1

        self.tasks.append(self.loop.create_task(self.zeromq_handler()))
        self.tasks.append(self.loop.create_task(self.watchdog()))
        self.connected.set_result(True)
        # if self.preload:
        #     self.loop.create_task(self.preload_block())
        #     self.loop.create_task(self.preload_block_hashes())
        self.loop.create_task(self.get_next_block())

    async def utxo_init(self):
        if self.utxo_data:
            if self.postgress_pool is None:
                raise Exception("UTXO data required postgresql db connection pool")

            async with self.postgress_pool.acquire() as conn:
                await conn.execute("""CREATE TABLE IF NOT EXISTS 
                                          connector_utxo (outpoint BYTEA,
                                                          data BYTEA,
                                                          PRIMARY KEY(outpoint));
                                   """)
                await conn.execute("""CREATE TABLE IF NOT EXISTS 
                                          connector_utxo_state (name VARCHAR,
                                                                value BIGINT,
                                                                PRIMARY KEY(name));
                                   """)
                lb = await conn.fetchval("SELECT value FROM connector_utxo_state WHERE name='last_block';")
                lc = await conn.fetchval("SELECT value FROM connector_utxo_state WHERE name='last_cached_block';")
                if lb is None:
                    lb = 0
                    lc = 0
                    await conn.execute("INSERT INTO connector_utxo_state (name, value) "
                                       "VALUES ('last_block', 0);")
                    await conn.execute("INSERT INTO connector_utxo_state (name, value) "
                                       "VALUES ('last_cached_block', 0);")
            self.last_block_height = lb
            self.last_block_utxo_cached_height = lc
            if self.app_block_height_on_start:
                if self.app_block_height_on_start < self.last_block_utxo_cached_height:
                    self.log.critical("UTXO state last block %s app state last block %s " % (self.last_block_height,
                                                                                             self.last_block_utxo_cached_height))
                    raise Exception("App blockchain state behind connector blockchain state")
                if self.app_block_height_on_start > self.last_block_height:
                    self.log.warning("Connector utxo height behind App height for %s blocks ..." %
                                     (self.app_block_height_on_start - self.last_block_height,))

            else:
                self.app_block_height_on_start = self.last_block_height


    async def zeromq_handler(self):
        while True:
            try:
                self.zmqContext = zmq.asyncio.Context()
                self.zmqSubSocket = self.zmqContext.socket(zmq.SUB)
                self.zmqSubSocket.setsockopt_string(zmq.SUBSCRIBE, "hashblock")
                if self.mempool_tx:
                    self.zmqSubSocket.setsockopt_string(zmq.SUBSCRIBE, "rawtx")
                self.zmqSubSocket.connect(self.zmq_url)
                self.log.info("Zeromq started")
                while True:
                    try:
                        msg = await self.zmqSubSocket.recv_multipart()
                        topic = msg[0]
                        body = msg[1]

                        if topic == b"hashblock":
                            self.last_zmq_msg = int(time.time())
                            if self.deep_synchronization:
                                continue
                            hash = body.hex()
                            self.log.warning("New block %s" % hash)
                            self.loop.create_task(self._get_block_by_hash(hash))

                        elif topic == b"rawtx":
                            self.last_zmq_msg = int(time.time())
                            if self.deep_synchronization or not self.mempool_tx:
                                continue
                            try:
                                self.loop.create_task(self._new_transaction(Transaction(body, format="raw")))
                            except:
                                self.log.critical("Transaction decode failed: %s" % body.hex())

                        if not self.active:
                            break
                    except asyncio.CancelledError:
                        self.log.warning("Zeromq handler terminating ...")
                        raise
                    except Exception as err:
                        self.log.error(str(err))

            except asyncio.CancelledError:
                self.zmqContext.destroy()
                self.log.warning("Zeromq handler terminated")
                break
            except Exception as err:
                self.log.error(str(err))
                await asyncio.sleep(1)
                self.log.warning("Zeromq handler reconnecting ...")
            if not self.active:
                self.log.warning("Zeromq handler terminated")
                break

    async def watchdog(self):
        """
        backup synchronization option
        in case zeromq failed
        """
        while True:
            try:
                while True:
                    await asyncio.sleep(10)
                    if int(time.time()) - self.last_zmq_msg > 300 and self.zmqContext:
                        self.log.error("ZerroMQ no messages about 5 minutes")
                        try:
                            self.zmqContext.destroy()
                            self.zmqContext = None
                        except:
                            pass
                    self.loop.create_task(self.get_next_block())
            except asyncio.CancelledError:
                self.log.info("connector watchdog terminated")
                break
            except Exception as err:
                self.log.error(str(traceback.format_exc()))
                self.log.error("watchdog error %s " % err)

    async def get_next_block(self):
        if self.active:
            if not self.get_next_block_mutex.done():
                await self.get_next_block_mutex
            try:
                self.get_next_block_mutex = asyncio.Future()

                if self.node_last_block <= self.last_block_height + self.backlog:
                    d = await self.rpc.getblockcount()
                    if d == self.node_last_block:
                        self.log.info("blockchain is synchronized with backlog %s" % self.backlog)
                        return
                    else:
                        self.node_last_block = d
                d = self.node_last_block - self.last_block_height

                if d > self.deep_sync_limit:
                    if not self.deep_synchronization:
                        self.log.warning("Deep synchronization mode")
                        self.deep_synchronization = True
                else:
                    if self.deep_synchronization:
                        self.log.warning("Normal synchronization mode")
                        self.deep_synchronization = False
                q = time.time()
                h = await self.rpc.getblockhash(self.last_block_height + 1)
                self.blocks_download_time += time.time() - q
                await self._get_block_by_hash(h)
            except Exception as err:
                self.log.error("get next block failed %s" % str(err))
            finally:
                self.get_next_block_mutex.set_result(True)

    async def _get_block_by_hash(self, hash):
        self.log.debug("get block by hash %s" % hash)
        try:
            block = self.block_hashes_preload.pop(hash)
            if not block:
                q = time.time()
                block = await self.rpc.getblock(hash)
                self.blocks_download_time += time.time() + q
            self.loop.create_task(self._new_block(block))
        except Exception:
            self.log.error("get block by hash %s FAILED" % hash)

    async def _new_block(self, block):
        if not self.active or not self.active_block.done() or self.last_block_height >= block["height"]:
            return
        self.active_block = asyncio.Future()
        self.log.debug("Block %s %s" % (block["height"], block["hash"]))
        bt = time.time()
        self.cache_loading = True if self.last_block_height < self.app_block_height_on_start else False

        try:
            tx_bin_list = [s2rh(h) for h in block["tx"]]
            await self.verify_block_position(block)

            if self.before_block_handler and not self.cache_loading:
                await self.before_block_handler(block)

            await self.fetch_block_transactions(block, tx_bin_list)

            if self.block_handler and not self.cache_loading:
                await self.block_handler(block)

            self.block_cache.set(block["hash"], block["height"])
            self.last_block_height = block["height"]
            if self.utxo_data:
                self.loop.create_task(self.utxo.save_utxo(block["height"]))

            self.blocks_processed_count += 1

            [self.tx_cache.pop(h) for h in tx_bin_list]

            tx_rate = round(self.total_received_tx / (time.time() - self.start_time), 4)
            if block["height"] % 200 == 0:
                self.log.info("Blocks %s; tx rate: %s;" % (block["height"], tx_rate))
                if self.utxo_data:
                    loading = "Loading ... " if self.cache_loading else ""
                    self.log.info(loading + "UTXO %s; hit rate: %s;" % (self.utxo.len(),
                                                                        self.utxo.hit_rate()))
                    self.log.info("Blocks download time %s;" % self.blocks_download_time)
                    self.log.info("Blocks decode time %s;" % self.blocks_decode_time)

            # after block added handler
            if self.after_block_handler and not self.cache_loading:
                try:
                    await self.after_block_handler(block)
                except:
                    pass

        except Exception as err:
            if self.await_tx:
                self.await_tx = set()
            self.log.error(str(traceback.format_exc()))
            self.log.error("block error %s" % str(err))
        finally:
            self.active_block.set_result(True)
            self.log.debug("%s block [%s tx/ %s size] processing time %s cache [%s/%s]" %
                          (block["height"],
                           len(block["tx"]),
                           block["size"] / 1000000,
                           tm(bt),
                           len(self.block_hashes_preload._store),
                           len(self.block_preload._store)))
            if self.node_last_block > self.last_block_height:
                self.loop.create_task(self.get_next_block())

    async def fetch_block_transactions(self, block, tx_bin_list):
        if not self.deep_synchronization:
            missed = set()
            for h in tx_bin_list:
                if self.tx_cache.get(h) is None:
                    missed.add(h)
        else:
            missed = list(tx_bin_list)
        self.log.debug("Transactions missed %s" % len(missed))

        q = time.time()
        if missed:
            self.missed_tx = set(missed)
            self.await_tx = set(missed)
            self.await_tx_future = {i: asyncio.Future() for i in missed}
            self.block_txs_request = asyncio.Future()
            if self.deep_synchronization or self.mempool_tx == False:
                self.loop.create_task(self._get_missed(block["hash"], block["time"], block["height"]))
            else:
                self.loop.create_task(self._get_missed(False, block["time"], block["height"]))
            try:
                await asyncio.wait_for(self.block_txs_request, timeout=self.block_timeout)
            except asyncio.CancelledError:
                # refresh rpc connection session
                await self.rpc.close()
                self.rpc = aiojsonrpc.rpc(self.rpc_url, self.loop, timeout=self.rpc_timeout)
                raise RuntimeError("block transaction request timeout")
        tx_count = len(block["tx"])
        self.total_received_tx += tx_count
        self.total_received_tx_time += time.time() - q

        rate = round(self.total_received_tx/self.total_received_tx_time)
        self.log.debug("Transactions received: %s [%s] received tx rate tx/s ->> %s <<" % (tx_count, time.time() - q, rate))

    async def verify_block_position(self, block):
        if self.block_cache.get(block["hash"]) is not None:
                self.log.error("duplicated block  %s" % block["hash"])
                raise Exception("duplicated block")
        if "previousblockhash" not in block :
            return
        lb = self.block_cache.get_last()
        if lb is None and not self.last_block_height:
            return
        if self.block_cache.get_last() != block["previousblockhash"]:
            if self.block_cache.get(block["previousblockhash"]) is None and self.last_block_height:
                self.log.critical("Connector error! Node out of sync "
                                  "no parent block in chain tail %s" % block["previousblockhash"])
                raise Exception("Node out of sync")

            if self.orphan_handler:
                await self.orphan_handler(self.last_block_height)
            self.block_cache.pop_last()
            self.last_block_height -= 1
            raise Exception("Sidebranch block removed")

    async def _get_missed(self, block_hash=False, block_time=None, block_height=None):
        if block_hash:
            try:
                block = self.block_preload.pop(block_hash)
                if not block:
                    t = time.time()
                    result = await self.rpc.getblock(block_hash, 0)
                    dt = time.time() - t
                    t = time.time()
                    block = decode_block_tx(result)
                    qt = time.time() - t
                    self.blocks_download_time += dt
                    self.blocks_decode_time += qt

                    self.log.debug("block downloaded %s decoded %s " % (round(dt, 4), round(qt, 4)))
                    for index, tx in enumerate(block):
                        try:
                            self.missed_tx.remove(block[tx]["txId"])
                            self.loop.create_task(self._new_transaction(block[tx], block_time, block_height, index))
                        except:
                            pass
            except Exception as err:
                self.log.error("_get_missed exception %s " % str(err))
                self.log.error(str(traceback.format_exc()))
                self.await_tx = set()
                self.block_txs_request.cancel()

        elif self.get_missed_tx_threads <= self.get_missed_tx_threads_limit:
            self.get_missed_tx_threads += 1
            # start more threads
            if len(self.missed_tx) > 1:
                self.loop.create_task(self._get_missed(False, block_time, block_height))
            while True:
                if not self.missed_tx:
                    break
                try:
                    batch = list()
                    while self.missed_tx:
                        batch.append(["getrawtransaction", self.missed_tx.pop()])
                        if len(batch) >= self.batch_limit:
                            break
                    result = await self.rpc.batch(batch)
                    for r in result:
                        try:
                            tx = Transaction(r["result"], format="raw")
                        except:
                            self.log.error("Transaction decode failed: %s" % r["result"])
                            raise Exception("Transaction decode failed")
                        self.loop.create_task(self._new_transaction(tx, block_time, None,  None))
                except Exception as err:
                    self.log.error("_get_missed exception %s " % str(err))
                    self.log.error(str(traceback.format_exc()))
                    self.await_tx = set()
                    self.block_txs_request.cancel()
            self.get_missed_tx_threads -= 1


    async def wait_block_dependences(self, tx):
        while self.await_tx_future:
            for i in tx["vIn"]:
                try:
                    if not self.await_tx_future[tx["vIn"][i]["txId"]].done():
                        await self.await_tx_future[tx["vIn"][i]["txId"]]
                        break
                except:
                    pass
            else:
                break


    async def _new_transaction(self, tx, block_time = None, block_height = None, block_index = None):
        if not(tx["txId"] in self.tx_in_process or self.tx_cache.get(tx["txId"])):
            try:
                self.tx_in_process.add(tx["txId"])
                if not tx["coinbase"]:
                    if block_height is not None:
                        await self.wait_block_dependences(tx)
                if self.utxo:
                    stxo = await self.get_stxo(tx, block_height, block_index)
                else:
                    stxo = None

                if self.tx_handler and  not self.cache_loading:
                    await self.tx_handler(tx, stxo, block_time, block_height, block_index)

                if self.utxo:
                    self.put_utxo(tx, block_height, block_index)

                self.tx_cache.set(tx["txId"], True)
                try:
                    self.await_tx.remove(tx["txId"])
                    if not self.await_tx_future[tx["txId"]].done():
                        self.await_tx_future[tx["txId"]].set_result(True)
                    if not self.await_tx:
                        self.block_txs_request.set_result(True)
                except:
                    pass
            except Exception as err:
                if tx["txId"] in self.await_tx:
                    self.await_tx = set()
                    self.block_txs_request.cancel()
                    for i in self.await_tx_future:
                        if not self.await_tx_future[i].done():
                            self.await_tx_future[i].cancel()
                self.log.debug("new transaction error %s " % err)
                self.log.debug(str(traceback.format_exc()))
            finally:
                self.tx_in_process.remove(tx["txId"])

    def put_utxo(self, tx, block_height, block_index):
        for i in tx["vOut"]:
            out = tx["vOut"][i]
            if self.skip_opreturn and out["nType"] in (3, 8):
                continue
            pointer = (block_height << 42) + (block_index << 21) + i
            if "addressHash" not in out:
                address = out["scriptPubKey"]
            else:
                address = b"%s%s" % (bytes([out["nType"]]), out["addressHash"])
            outpoint = b"%s%s" % (tx["txId"], int_to_bytes(i))
            self.utxo.set(outpoint, pointer, out["value"], address)

    async def get_stxo(self, tx, block_height, block_index):
        stxo, missed = set(), set()
        block_height = 0 if block_height is None else block_height
        block_index = 0 if block_index is None else block_index

        for i in tx["vIn"]:
            inp = tx["vIn"][i]
            outpoint = b"%s%s" % (inp["txId"], int_to_bytes(inp["vOut"]))
            r = self.utxo.get(outpoint, block_height)
            stxo.add(r) if r else missed.add((outpoint, (block_height << 42) + (block_index << 21) + i))

        if missed:
            await self.utxo.load_utxo()
            [stxo.add(self.utxo.get_loaded(o, block_height)) for o, s in missed]

        if len(stxo) != len(tx["vIn"]):
            self.log.critical("utxo get failed " + rh2s(tx["txId"]))
            self.log.critical(str(stxo))
            raise Exception("utxo get failed ")
        return stxo


    async def preload_block_hashes(self):
        while True:
            try:
                start_height = self.last_block_height
                height = start_height + 10
                d = await self.rpc.getblockcount()
                if d > height:
                    while True:
                        height += 1
                        d = await self.rpc.getblockhash(height)
                        ex = self.block_preload.get(d)
                        if not ex:
                            b = await self.rpc.getblock(d)
                            self.block_hashes_preload.set(d, b)
                        if start_height + 15000 < height:
                            break
            except asyncio.CancelledError:
                self.log.info("connector preload_block_hashes terminated")
                break
            except:
                pass
            await asyncio.sleep(10)

    async def preload_block(self):
        while True:
            try:
                start_height = self.last_block_height
                height = start_height + 10
                d = await self.rpc.getblockcount()
                if d > height:
                    while True:
                        height += 1
                        d = await self.rpc.getblockhash(height)
                        ex = self.block_preload.get(d)
                        if not ex:
                            b = await self.rpc.getblock(d, 0)
                            block = decode_block_tx(b)
                            self.block_preload.set(d, block)
                        if start_height + 15000 < height:
                            break
            except asyncio.CancelledError:
                self.log.info("connector preload_block terminated")
                break
            except:
                pass
            await asyncio.sleep(15)


    async def stop(self):
        self.active = False
        self.log.warning("New block processing restricted")
        self.log.warning("Stopping node connector ...")
        [task.cancel() for task in self.tasks]
        await asyncio.wait(self.tasks)
        if not self.active_block.done():
            self.log.warning("Waiting active block task ...")
            await self.active_block
        await self.rpc.close()
        if self.zmqContext:
            self.zmqContext.destroy()
        self.log.warning('Node connector terminated')


class UTXO():
    def __init__(self, db_pool, loop, log, cache_size):
        self.cached = OrderedDict()
        self.missed = set()
        self.destroyed = OrderedDict()
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

    def set(self, outpoint, pointer, amount, address):
        if len(self.cached) > self._cache_size and not self.save_process:
            self.loop.create_task(self.save_utxo())
        self.cached[outpoint] = (pointer, amount, address)
        if pointer:
            self.last_cached_block = pointer >> 42

    def remove(self, outpoint):
        del self.cached[outpoint]

    async def save_utxo(self, block_height):
        # save to db tail from cache
        block_height -= self.maturity
        if block_height > 0 and not self.save_process:
            c = len(self.cached) - self._cache_size
            try:
                self.save_process = True

                for key in iter(self.destroyed):
                    if key < block_height:
                        n = set()
                        for i in self.destroyed[key]:
                            try:
                                del self.cached[i]
                            except:
                                try:
                                    del self.loaded[i]
                                    n.add(i)
                                except:
                                    pass
                        self.destroyed[key] = n


                ln, rs, lb = set(), set(), 0
                for key in iter(self.cached):
                    i = self.cached[key]
                    if (c>0 or lb == i[0] >> 42) and (i[0] >> 42) < block_height:
                        rs.add((key,b"".join((int_to_c_int(i[0]),
                                             int_to_c_int(i[1]),
                                             i[2]))))
                        ln.add(key)
                        lb = i[0] >> 42
                        c -= 1
                        continue
                    break


                r = set()
                db = set()
                for key in iter(self.destroyed):
                    if key <= lb and key < block_height:
                        db.add(key)
                        [r.add(i) for i in self.destroyed[key]]

                # insert to db
                async with self._db_pool.acquire() as conn:
                    async with conn.transaction():
                        await conn.execute("DELETE FROM connector_utxo WHERE "
                                           "outpoint = ANY($1);", r)
                        await conn.copy_records_to_table('connector_utxo',  columns=["outpoint", "data"], records=rs)
                        await conn.execute("UPDATE connector_utxo_state SET value = %s "
                                           "WHERE name = 'last_block';", lb)
                        await conn.execute("UPDATE connector_utxo_state SET value = %s "
                                           "WHERE name = 'last_cached_block';", block_height)

                # remove from cache
                for key in ln:
                    try:
                        self.cached.pop(key)
                    except:
                        pass

                [self.destroyed.pop(key) for key in db]
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
                rows = await conn.fetch("SELECT outpoint, utxo.data FROM connector_utxo "
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
        finally:
            self.load_utxo_future.set_result(True)


    def len(self):
        return len(self.cached)

    def hit_rate(self):
        if self._requests:
            return self._hit / self._requests
        else:
            return 0



def get_stream(stream):
    if not isinstance(stream, io.BytesIO):
        if isinstance(stream, str):
            stream = bytes.fromhex(stream)
        if isinstance(stream, bytes):
            stream = io.BytesIO(stream)
        else:
            raise TypeError("object should be bytes or HEX encoded string")
    return stream


def decode_block_tx(block):
    stream = get_stream(block)
    stream.seek(80)
    return {i: Transaction(stream, format="raw") for i in range(var_int_to_int(read_var_int(stream)))}


class DependsTransaction(Exception):
    def __init__(self, raw_tx_hash):
        self.raw_tx_hash = raw_tx_hash


class Cache():
    def __init__(self, max_size=1000):
        self._store = OrderedDict()
        self._max_size = max_size
        self.clear_tail = False
        self._requests = 0
        self._hit = 0

    def set(self, key, value):
        self._check_limit()
        self._store[key] = value

    def _check_limit(self):
        if len(self._store) >= self._max_size:
            self.clear_tail = True
        if self.clear_tail:
            if len(self._store) >= int(self._max_size * 0.75):
                [self._store.popitem(last=False) for i in range(20)]
            else:
                self.clear_tail = False

    def get(self, key):
        self._requests += 1
        try:
            i = self._store[key]
            self._hit += 1
            return i
        except:
            return None

    def pop(self, key):
        self._requests += 1
        try:
            data = self._store[key]
            del self._store[key]
            self._hit += 1
            return data
        except:
            return None

    def pop_last(self):
        try:
            i = next(reversed(self._store))
            data = self._store[i]
            del self._store[i]
            return data
        except:
            return None

    def get_last(self):
        try:
            i = next(reversed(self._store))
            data = self._store[i]
            return data
        except:
            return None

    def len(self):
        return len(self._store)

    def hitrate(self):
        if self._requests:
            return self._hit / self._requests
        else:
            return 0


def tm(p=None):
    if p is not None:
        return round(time.time() - p, 4)
    return time.time()

