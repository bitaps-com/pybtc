from pybtc.functions.tools import rh2s, s2rh
from pybtc.functions.tools import var_int_to_int, var_int_len
from pybtc.functions.tools import read_var_int
from pybtc.functions.hash import double_sha256
from pybtc.transaction import Transaction
from pybtc import int_to_c_int, c_int_to_int, c_int_len, int_to_bytes
from pybtc.functions.block import bits_to_target, target_to_difficulty
from struct import unpack, pack
import sys
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
                 rpc_batch_limit=50, rpc_threads_limit=100, rpc_timeout=100,
                 utxo_data=False,
                 utxo_cache_size=1000000,
                 skip_opreturn=True,
                 block_preload_cache_limit= 1000 * 1000000,
                 block_hashes_cache_limit= 200 * 1000000,
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
        self.utxo_test = dict()

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
        self.get_next_block_mutex = False
        self.active_block = asyncio.Future()
        self.active_block.set_result(True)
        self.last_zmq_msg = int(time.time())
        self.total_received_tx = 0
        self.total_received_tx_stat = 0
        self.blocks_processed_count = 0
        self.blocks_decode_time = 0
        self.blocks_download_time = 0
        self.tx_processing_time = 0
        self.non_cached_blocks = 0
        self.total_received_tx_time = 0
        self.start_time = time.time()

        # cache and system
        self.block_preload_cache_limit = block_preload_cache_limit
        self.block_hashes_cache_limit = block_hashes_cache_limit
        self.tx_cache_limit = 100 * 100000
        self.block_headers_cache_limit = 100 * 100000
        self.block_preload = Cache(max_size=self.block_preload_cache_limit, clear_tail=False)
        self.block_hashes = Cache(max_size=self.block_hashes_cache_limit)
        self.block_hashes_preload_mutex = False
        self.tx_cache = Cache(max_size=self.tx_cache_limit)
        self.block_headers_cache = Cache(max_size=self.block_headers_cache_limit)

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
                self.log.warning("%s blocks before synchronization" % d)
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
            self.block_headers_cache.set(row, h)
            h -= 1

        self.tasks.append(self.loop.create_task(self.zeromq_handler()))
        self.tasks.append(self.loop.create_task(self.watchdog()))
        self.connected.set_result(True)
        # if self.preload:
        #     self.loop.create_task(self.preload_block())
        #     self.loop.create_task(self.preload_block_hashes())
        self.get_next_block_mutex = True
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
                self.app_block_height_on_start = self.last_block_utxo_cached_height


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
                    await asyncio.sleep(20)
                    if int(time.time()) - self.last_zmq_msg > 300 and self.zmqContext:
                        self.log.error("ZerroMQ no messages about 5 minutes")
                        try:
                            self.zmqContext.destroy()
                            self.zmqContext = None
                        except:
                            pass
                    if not self.get_next_block_mutex:
                        self.get_next_block_mutex = True
                        self.loop.create_task(self.get_next_block())
            except asyncio.CancelledError:
                self.log.info("connector watchdog terminated")
                break
            except Exception as err:
                self.log.error(str(traceback.format_exc()))
                self.log.error("watchdog error %s " % err)

    async def get_next_block(self):
        if self.active and self.active_block.done() and self.get_next_block_mutex:
            try:
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
                        # clear preload caches
                        self.deep_synchronization = False

                if self.deep_synchronization:
                    raw_block = self.block_preload.pop(self.last_block_height + 1)
                    if raw_block:
                        q = time.time()
                        block = decode_block_tx(raw_block)
                        self.blocks_decode_time += time.time() - q
                    else:
                        h = self.block_hashes.pop(self.last_block_height + 1)
                        if h is None:
                            h = await self.rpc.getblockhash(self.last_block_height + 1)
                            if not self.block_hashes_preload_mutex:
                                self.loop.create_task(self.preload_blocks())
                        block = await self._get_block_by_hash(h)
                else:
                    h = await self.rpc.getblockhash(self.last_block_height + 1)
                    block = await self._get_block_by_hash(h)


                self.loop.create_task(self._new_block(block))
            except Exception as err:
                self.log.error("get next block failed %s" % str(err))
            finally:
                self.get_next_block_mutex = False

    async def _get_block_by_hash(self, hash):
        self.log.debug("get block by hash %s" % hash)
        try:
            if self.deep_synchronization:
                q = time.time()
                self.non_cached_blocks += 1
                raw_block = await self.rpc.getblock(hash, 0)
                self.blocks_download_time += time.time() - q
                q = time.time()
                block = decode_block_tx(raw_block)
                self.blocks_decode_time += time.time() - q
            else:
                q = time.time()
                block = await self.rpc.getblock(hash)
                self.blocks_download_time += time.time() - q
            return block
        except Exception:
            self.log.error("get block by hash %s FAILED" % hash)
            self.log.error(str(traceback.format_exc()))

    async def _new_block(self, block):
        try:
            if self.block_headers_cache.get(block["hash"]) is not None:
                    return

            if self.deep_synchronization:
                block["height"] = self.last_block_height + 1
            if not self.active or not self.active_block.done() or self.last_block_height >= block["height"]:
                return
            self.active_block = asyncio.Future()

            self.log.debug("Block %s %s" % (block["height"], block["hash"]))
            bt = time.time()
            self.cache_loading = True if self.last_block_height < self.app_block_height_on_start else False


            if self.deep_synchronization:
                tx_bin_list = [block["rawTx"][i]["txId"] for i in block["rawTx"]]
            else:
                tx_bin_list = [s2rh(h) for h in block["tx"]]
            await self.verify_block_position(block)

            if self.before_block_handler and not self.cache_loading:
                await self.before_block_handler(block)

            await self.fetch_block_transactions(block, tx_bin_list)

            if self.block_handler and not self.cache_loading:
                await self.block_handler(block)

            self.block_headers_cache.set(block["hash"], block["height"])
            self.last_block_height = block["height"]
            if self.utxo_data:
                self.utxo.destroy_utxo(block["height"])

            self.blocks_processed_count += 1

            [self.tx_cache.pop(h) for h in tx_bin_list]

            tx_rate = round(self.total_received_tx / (time.time() - self.start_time), 4)
            t = 10000 if not self.deep_synchronization else 10000
            if (self.total_received_tx - self.total_received_tx_stat) > t:
                self.total_received_tx_stat = self.total_received_tx
                self.log.warning("Blocks %s; tx rate: %s;" % (block["height"], tx_rate))
                if self.utxo_data:
                    loading = "Loading ... " if self.cache_loading else ""
                    self.log.info(loading + "UTXO %s; hit rate: %s;" % (self.utxo.len(),
                                                                        self.utxo.hit_rate()))
                    self.log.info("Blocks downloaded  %s; decoded %s" % (round(self.blocks_download_time, 4),
                                                                         round(self.blocks_decode_time, 4)))
                    if self.deep_synchronization:
                        self.log.info("Blocks not cached %s; "
                                      "cache count %s; "
                                      "cache size %s M;" % (self.non_cached_blocks,
                                                            self.block_preload.len(),
                                                            round(self.block_preload._store_size / 1024 / 1024, 2)))
                        self.log.info(
                                      "cache first %s; "
                                      "cache last %s;" % (
                                                            next(iter(self.block_preload._store)),
                                                            next(reversed(self.block_preload._store))))

                        self.log.info("saved utxo block %s; "
                                      "saved utxo %s; "
                                      "deleted utxo %s; "
                                      "loaded utxo %s; "% (self.utxo.last_saved_block,
                                                                  self.utxo.saved_utxo,
                                                                   self.utxo.deleted_utxo,
                                                                   self.utxo.loaded_utxo
                                                           ))
                        self.log.info(
                                      "destroyed utxo %s; "
                                      "destroyed utxo block %s; "
                                      "outs total %s;" % (
                                                           self.utxo.destroyed_utxo,
                                                           self.utxo.destroyed_utxo_block,
                                                           self.utxo.outs_total
                                                           ))
                self.log.info("total tx fetch time %s;" % self.total_received_tx_time)

            # after block added handler
            if self.after_block_handler and not self.cache_loading:
                try:
                    await self.after_block_handler(block)
                except:
                    pass

        except Exception as err:
            if self.await_tx:
                self.await_tx = set()
            for i in self.await_tx_future:
                if not self.await_tx_future[i].done():
                    self.await_tx_future[i].cancel()
            self.await_tx_future = dict()
            self.log.error(str(traceback.format_exc()))
            self.log.error("block error %s" % str(err))
        finally:
            self.active_block.set_result(True)
            # self.log.debug("%s block [%s tx/ %s size] processing time %s cache [%s/%s]" %
            #               (block["height"],
            #                len(block["tx"]),
            #                block["size"] / 1000000,
            #                tm(bt),
            #                len(self.block_hashes._store),
            #                len(self.block_preload._store)))
            if self.node_last_block > self.last_block_height:
                self.get_next_block_mutex = True
                self.loop.create_task(self.get_next_block())

    async def fetch_block_transactions(self, block, tx_bin_list):
        q = time.time()
        if self.deep_synchronization:
            self.await_tx = set(tx_bin_list)
            self.await_tx_future = {i: asyncio.Future() for i in tx_bin_list}
            self.block_txs_request = asyncio.Future()
            for i in block["rawTx"]:
                self.loop.create_task(self._new_transaction(block["rawTx"][i],
                                                            block["time"],
                                                            block["height"],
                                                            i))
            await asyncio.wait_for(self.block_txs_request, timeout=1500)


        elif tx_bin_list:
            raise Exception("not emplemted")
            missed = list(tx_bin_list)
            self.log.debug("Transactions missed %s" % len(missed))

            if missed:
                self.missed_tx = set(missed)
                self.await_tx = set(missed)
                self.await_tx_future = {i: asyncio.Future() for i in missed}
                self.block_txs_request = asyncio.Future()
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
        if "previousblockhash" not in block :
            return
        if self.block_headers_cache.len() == 0:
            return

        lb = self.block_headers_cache.get_last_key()
        if self.block_headers_cache.get_last_key() != block["previousblockhash"]:
            if self.block_headers_cache.get(block["previousblockhash"]) is None and self.last_block_height:
                self.log.critical("Connector error! Node out of sync "
                                  "no parent block in chain tail %s" % block["previousblockhash"])
                raise Exception("Node out of sync")

            if self.orphan_handler:
                await self.orphan_handler(self.last_block_height)
            self.block_headers_cache.pop_last()
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
                stxo = None
                self.tx_in_process.add(tx["txId"])
                if not tx["coinbase"]:
                    if block_height is not None:
                        await self.wait_block_dependences(tx)
                    # if self.utxo:
                    #     stxo = await self.get_stxo(tx, block_height, block_index)

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
                address = b"".join((bytes([out["nType"]]), out["addressHash"]))
            outpoint = b"".join((tx["txId"], int_to_bytes(i)))
            self.utxo_test[outpoint] = (pointer, out["value"], address)
            # self.utxo.set(outpoint, pointer, out["value"], address)

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

        if len(stxo) != len(tx["vIn"]) and not self.cache_loading:
            self.log.critical("utxo get failed " + rh2s(tx["txId"]))
            self.log.critical(str(stxo))
            raise Exception("utxo get failed ")
        return stxo


    async def preload_blocks(self):
        if self.block_hashes_preload_mutex:
            return
        try:
            self.block_hashes_preload_mutex = True
            max_height = self.node_last_block - self.deep_synchronization
            height = self.last_block_height + 1
            processed_height = self.last_block_height

            while height < max_height:
                if self.block_preload._store_size < self.block_preload_cache_limit:
                    try:
                        if height < self.last_block_height:
                            height = self.last_block_height + 1
                        batch = list()
                        h_list = list()
                        while True:
                            batch.append(["getblockhash", height])
                            h_list.append(height)
                            if len(batch) >= self.batch_limit or height >= max_height:
                                height += 1
                                break
                            height += 1
                        result = await self.rpc.batch(batch)
                        h = list()
                        batch = list()
                        for lh, r in zip(h_list, result):
                            try:
                                self.block_hashes.set(lh, r["result"])
                                batch.append(["getblock", r["result"], 0])
                                h.append(lh)
                            except:
                                pass

                        blocks = await self.rpc.batch(batch)

                        for x,y in zip(h,blocks):
                            try:
                                self.block_preload.set(x, (y["result"]))
                            except:
                                pass

                    except asyncio.CancelledError:
                        self.log.info("connector preload_block_hashes failed")
                        break
                    except:
                        pass
                if processed_height < self.last_block_height:
                    for i in range(processed_height, self.last_block_height ):
                        try:
                            self.block_preload.remove(i)
                        except:
                            pass
                    processed_height = self.last_block_height
                if next(iter(self.block_preload._store)) <  processed_height + 1:
                    for i in range(next(iter(self.block_preload._store)), self.last_block_height+1):
                        try:
                            self.block_preload.remove(i)
                        except:
                            pass
                if self.block_preload._store_size < self.block_preload_cache_limit * 0.9:
                    continue

                await asyncio.sleep(10)
                # remove unused items

        finally:
            self.block_hashes_preload_mutex = False


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
        self.deleted = OrderedDict()
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
            self.destroyed.pop(key)

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
    s = get_stream(block)
    b = dict()
    b["amount"] = 0
    b["strippedSize"] = 80
    b["version"] = unpack("<L", s.read(4))[0]
    b["versionHex"] = pack(">L", b["version"]).hex()
    b["previousBlockHash"] = rh2s(s.read(32))
    b["merkleRoot"] = rh2s(s.read(32))
    b["time"] = unpack("<L", s.read(4))[0]
    b["bits"] = s.read(4)
    b["target"] = bits_to_target(unpack("<L", b["bits"])[0])
    b["targetDifficulty"] = target_to_difficulty(b["target"])
    b["target"] = b["target"].to_bytes(32, byteorder="little")
    b["nonce"] = unpack("<L", s.read(4))[0]
    s.seek(-80, 1)
    b["header"] = s.read(80).hex()
    b["bits"] = rh2s(b["bits"])
    b["target"] = rh2s(b["target"])
    b["hash"] = double_sha256(b["header"], hex=0)
    b["hash"] = rh2s(b["hash"])

    b["rawTx"] = {i: Transaction(s, format="raw")
                  for i in range(var_int_to_int(read_var_int(s)))}
    b["tx"] = [rh2s(b["rawTx"][i]["txId"]) for i in b["rawTx"] ]
    b["size"] = len(block)
    for t in b["rawTx"].values():
        b["amount"] += t["amount"]
        b["strippedSize"] += t["bSize"]
    b["strippedSize"] += var_int_len(len(b["tx"]))
    b["weight"] = b["strippedSize"] * 3 + b["size"]
    return b


class DependsTransaction(Exception):
    def __init__(self, raw_tx_hash):
        self.raw_tx_hash = raw_tx_hash


class Cache():
    def __init__(self, max_size=1000000, clear_tail=True):
        self._store = OrderedDict()
        self._store_size = 0
        self._max_size = max_size
        self.clear_tail = False
        self.clear_tail_auto = clear_tail
        self._requests = 0
        self._hit = 0

    def set(self, key, value):
        self._check_limit()
        self._store[key] = value
        self._store_size += sys.getsizeof(value) + sys.getsizeof(key)

    def _check_limit(self):
        if self._store_size >= self._max_size:
            self.clear_tail = True
        if self.clear_tail and self.clear_tail_auto:
            if self._store_size >= int(self._max_size * 0.75):
                try:
                    [self.pop_last() for i in range(20)]
                except:
                    pass
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
            data = self._store.pop(key)
            self._store_size -= sys.getsizeof(data) + sys.getsizeof(key)
            self._hit += 1
            return data
        except:
            return None

    def remove(self, key):
        try:
            data = self._store.pop(key)
            self._store_size -= sys.getsizeof(data) + sys.getsizeof(key)
        except:
            pass

    def pop_last(self):
        try:
            i = next(reversed(self._store))
            data = self._store[i]
            del self._store[i]
            self._store_size -= sys.getsizeof(data) + sys.getsizeof(i)
            return data
        except:
            return None

    def get_last_key(self):
        try:
            i = next(reversed(self._store))
            return i
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

