from pybtc.functions.tools import rh2s, s2rh
from pybtc.connector.block_loader import BlockLoader
from pybtc.connector.utxo import UTXO
from pybtc.connector.utils import decode_block_tx
from pybtc.connector.utils import Cache
from pybtc.transaction import Transaction
from pybtc import int_to_bytes, bytes_to_int

import traceback
import aiojsonrpc
import zmq
import zmq.asyncio
import asyncio
import time
from _pickle import loads

class Connector:

    def __init__(self, node_rpc_url, node_zerromq_url, logger,
                 last_block_height=0, chain_tail=None,
                 tx_handler=None, orphan_handler=None,
                 before_block_handler=None, block_handler=None, after_block_handler=None,
                 block_batch_handler=None,
                 block_timeout=30,
                 deep_sync_limit=20, backlog=0, mempool_tx=True,
                 rpc_batch_limit=50, rpc_threads_limit=100, rpc_timeout=100,
                 utxo_data=False,
                 utxo_cache_size=1000000,
                 skip_opreturn=True,
                 block_cache_workers= 4,
                 block_preload_cache_limit= 1000 * 1000000,
                 block_hashes_cache_limit= 200 * 1000000,
                 db_type=None,
                 db=None):
        self.loop = asyncio.get_event_loop()

        # settings
        self.log = logger
        self.rpc_url = node_rpc_url
        self.rpc_timeout = rpc_timeout
        self.rpc_batch_limit = rpc_batch_limit
        self.zmq_url = node_zerromq_url
        self.orphan_handler = orphan_handler
        self.block_timeout = block_timeout
        self.tx_handler = tx_handler
        self.skip_opreturn = skip_opreturn
        self.before_block_handler = before_block_handler
        self.block_handler = block_handler
        self.after_block_handler = after_block_handler
        self.block_batch_handler = block_batch_handler
        self.deep_sync_limit = deep_sync_limit
        self.backlog = backlog
        self.mempool_tx = mempool_tx
        self.db_type = db_type
        self.db = db
        self.utxo_cache_size = utxo_cache_size
        self.block_cache_workers = block_cache_workers
        self.utxo_data = utxo_data
        self.chain_tail = list(chain_tail) if chain_tail else []


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
        self.blocks_processing_time = 0
        self.tx_processing_time = 0
        self.non_cached_blocks = 0
        self.total_received_tx_time = 0
        self.coins = 0
        self.op_return = 0
        self.destroyed_coins = 0
        self.preload_cached_total = 0
        self.preload_cached = 0
        self.preload_cached_annihilated = 0
        self.start_time = time.time()
        self.total_received_tx_last = 0
        self.start_time_last = time.time()
        self.batch_time = time.time()
        self.batch_load_utxo = 0
        self.batch_parsing = 0
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
                self.log.info("Blockchain is synchronized")
            else:
                d = self.node_last_block - self.last_block_height
                self.log.info("%s blocks before synchronization" % d)
                if d > self.deep_sync_limit:
                    self.log.info("Deep synchronization mode")
                    self.deep_synchronization = True
            break

        if self.utxo_data:
            self.utxo = UTXO(self.db_type, self.db,
                             self.loop, self.log,
                             self.utxo_cache_size if self.deep_synchronization else 0)

        h = self.last_block_height
        if h < len(self.chain_tail):
            raise Exception("Chain tail len not match last block height")
        for row in reversed(self.chain_tail):
            self.block_headers_cache.set(row, h)
            h -= 1
        self.block_loader = BlockLoader(self,workers = self.block_cache_workers)

        self.tasks.append(self.loop.create_task(self.zeromq_handler()))
        self.tasks.append(self.loop.create_task(self.watchdog()))
        self.connected.set_result(True)
        self.get_next_block_mutex = True
        self.loop.create_task(self.get_next_block())

    async def utxo_init(self):
        if self.utxo_data:
            if self.db_type is None:
                raise Exception("UTXO data required  db connection")
            if self.db_type not in ("rocksdb", "leveldb", "postgresql"):
                raise Exception("Connector supported database types is: rocksdb, leveldb, postgresql")
            if self.db_type in ("rocksdb", "leveldb"):
                # rocksdb and leveldb
                lb = self.db.get(b"last_block")
                if lb is None:
                    lb = 0
                    self.db.put(b"last_block", int_to_bytes(0))
                    self.db.put(b"last_cached_block", int_to_bytes(0))
                else:
                    lb = bytes_to_int(lb)
                lc = bytes_to_int(self.db.get(b"last_cached_block"))
            else:
                # postgresql
                async with self.db.acquire() as conn:
                    await conn.execute("""CREATE TABLE IF NOT EXISTS 
                                              connector_utxo (outpoint BYTEA,
                                                              pointer BIGINT,
                                                              address BYTEA,
                                                              amount  BIGINT,
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
                        self.log.info("Blockchain is synchronized with backlog %s" % self.backlog)
                        return
                    else:
                        self.node_last_block = d
                d = self.node_last_block - self.last_block_height

                if d > self.deep_sync_limit:
                    if not self.deep_synchronization:
                        self.log.info("Deep synchronization mode")
                        self.deep_synchronization = True
                else:
                    if self.deep_synchronization:
                        self.log.info("Normal synchronization mode")
                        # clear preload caches
                        self.deep_synchronization = False
                block = None
                if self.deep_synchronization:
                    raw_block = self.block_preload.pop(self.last_block_height + 1)
                    if raw_block:
                        q = time.time()
                        block = loads(raw_block)
                        block["hash"]
                        self.blocks_decode_time += time.time() - q

                if not block:
                    h = await self.rpc.getblockhash(self.last_block_height + 1)
                    block = await self._get_block_by_hash(h)
                    block["checkpoint"] = self.last_block_height + 1
                    block["height"] = self.last_block_height + 1

                self.loop.create_task(self._new_block(block))
            except Exception as err:
                self.log.error("get next block failed %s" % str(err))
            finally:
                self.get_next_block_mutex = False

    async def _get_block_by_hash(self, hash):
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
        if not self.active: return
        tq = time.time()
        if self.block_headers_cache.get(block["hash"]) is not None: return
        if self.deep_synchronization:  block["height"] = self.last_block_height + 1
        if self.last_block_height >= block["height"]:  return
        if not self.active_block.done():  return

        try:
            self.active_block = asyncio.Future()
            self.cache_loading = True if self.last_block_height < self.app_block_height_on_start else False

            if not self.deep_synchronization:
                if not  self.block_batch_handler:
                    tx_bin_list = [block["rawTx"][i]["txId"] for i in block["rawTx"]]
            else:
                tx_bin_list = [s2rh(h) for h in block["tx"]]
            await self.verify_block_position(block)

            if self.before_block_handler and not self.cache_loading:
                await self.before_block_handler(block)
            if self.deep_synchronization and self.block_batch_handler:
                await self._block_as_transactions_batch(block)
            else:
                await self.fetch_block_transactions(block, tx_bin_list)

            if self.utxo_data:
                checkpoint = self.utxo.checkpoint
                try: self.utxo.checkpoints.append(block["checkpoint"])
                except: pass
                if len(self.utxo.cached) > self.utxo.size_limit and \
                   not self.utxo.save_process and \
                   self.utxo.checkpoints:
                    if self.utxo.checkpoints[0] < block["height"]:
                        self.utxo.deleted_last_block = block["height"]
                        self.utxo.pending_deleted = self.utxo.pending_deleted | self.utxo.deleted
                        self.utxo.deleted = set()
                        self.utxo.create_checkpoint()
            else:
                checkpoint = None

            if self.block_batch_handler and not self.cache_loading:
                await self.block_batch_handler(block, checkpoint)

            if self.block_handler and not self.cache_loading:
                await self.block_handler(block)

            self.block_headers_cache.set(block["hash"], block["height"])
            self.last_block_height = block["height"]

            if self.utxo_data and self.utxo.save_process:
                self.loop.create_task(self.utxo.save_checkpoint())


            self.blocks_processed_count += 1
            if not (self.deep_synchronization and self.block_batch_handler):
                for h in tx_bin_list:
                    self.tx_cache.pop(h)

            t = 10000 if not self.deep_synchronization else 100000
            if (self.total_received_tx - self.total_received_tx_stat) > t:
                tx_rate = round(self.total_received_tx / (time.time() - self.start_time), 4)
                io_rate = round((self.coins + self.destroyed_coins) / (time.time() - self.start_time), 4)
                tx_rate_last = round(self.total_received_tx_last / (time.time() - self.start_time_last), 4)
                self.total_received_tx_last = 0
                self.start_time_last = time.time()
                batch_tx_count = self.total_received_tx - self.total_received_tx_stat
                self.total_received_tx_stat = self.total_received_tx
                self.log.info("Blocks %s; tx rate: %s; io rate[%s];" % (block["height"], tx_rate, io_rate))
                if self.utxo_data:
                    loading = "Loading ... " if self.cache_loading else ""
                    if self.deep_synchronization:
                        self.log.debug("- Batch ---------------")
                        self.log.debug("    Rate %s; transactions %s" % (tx_rate_last, batch_tx_count))
                        self.log.debug("    Load utxo %s; parsing %s" % (self.batch_load_utxo,
                                                                         self.batch_parsing))
                        self.batch_load_utxo = 0
                        self.batch_parsing = 0

                        self.log.debug("- Blocks --------------")

                        self.log.debug("    Blocks not cached %s; "
                                      "blocks cached %s; "
                                      "cache size %s M;" % (self.non_cached_blocks,
                                                            self.block_preload.len(),
                                                            round(self.block_preload._store_size / 1024 / 1024, 2)))
                        self.log.debug("    Cache first block %s; "
                                       "cache last block %s;" % (next(iter(self.block_preload._store)),
                                                                 next(reversed(self.block_preload._store))))
                        self.log.debug("    Preload coins cache -> %s:%s [%s] "
                                       "preload cache efficiency %s;" % (self.preload_cached,
                                                                          self.preload_cached_annihilated,
                                                                          self.preload_cached_total,
                                                                          round(self.preload_cached_total
                                                                                / self.destroyed_coins, 4)))

                        self.log.debug("- UTXO ----------------")
                        if loading: self.log.debug(loading)

                        self.log.debug("    Cache count %s; hit rate: %s;" % (self.utxo.len(),
                                                                          round(self.utxo.hit_rate(), 4)))
                        self.log.debug("    Checkpoint block %s; saved to db %s; "
                                       "deleted from db %s; "
                                       "loaded utxo from db %s; "% (self.utxo.last_saved_block,
                                                                    self.utxo.saved_utxo,
                                                                    self.utxo.deleted_utxo,
                                                                    self.utxo.loaded_utxo))
                        if self.utxo.read_from_db_time_total:
                           c =  round(self.utxo.read_from_db_count / self.utxo.read_from_db_batch_time, 4)
                        else:
                            c = 0
                        self.log.debug("    Read from db last batch %s; "
                                       "count %s; "
                                       "batch time %s; "
                                       "rate %s; "
                                       "total time %s; " % (round(self.utxo.read_from_db_time, 4),
                                                            self.utxo.read_from_db_count,
                                                            round(self.utxo.read_from_db_batch_time, 4),
                                                            c,
                                                            int(self.utxo.read_from_db_time_total)))
                        self.utxo.read_from_db_batch_time = 0
                        self.utxo.read_from_db_time = 0
                        self.utxo.read_from_db_count = 0
                self.log.debug("- Coins ---------------")
                self.log.debug("    Coins %s; destroyed %s; "
                               "unspent %s; op_return %s;" % (self.coins,
                                                              self.destroyed_coins,
                                                              self.coins - self.destroyed_coins,
                                                              self.op_return))
                self.log.debug("    Coins destroyed in cache %s; "
                               "cache efficiency  %s [%s];" % (self.utxo._hit,
                                                               round( self.utxo._hit / self.destroyed_coins, 4),
                                                               round((self.utxo._hit + self.preload_cached_annihilated)
                                                                      / self.destroyed_coins, 4)))
                self.log.debug("---------------------")
                t = int(time.time() - self.start_time)
                t2 = round(time.time() - self.batch_time, 2)
                self.batch_time = time.time()
                h, m, s = t // 3600, (t % 3600 ) // 60, (t % 3600) % 60
                self.log.info("Total time %s:%s:%s;  batch time: %s" % (h,m,s, t2))
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
            if self.node_last_block > self.last_block_height:
                self.get_next_block_mutex = True
                self.loop.create_task(self.get_next_block())
            self.blocks_processing_time += time.time() - tq
            self.active_block.set_result(True)

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
        self.total_received_tx_last += tx_count
        self.total_received_tx_time += time.time() - q
        rate = round(self.total_received_tx/self.total_received_tx_time)
        self.log.debug("Transactions received: %s [%s] received tx rate tx/s ->> %s <<" % (tx_count, time.time() - q, rate))

    async def _block_as_transactions_batch(self, block):
        try:
            t2 = 0
            t = time.time()
            if self.utxo:
                for q in block["rawTx"]:
                    tx = block["rawTx"][q]
                    for i in tx["vOut"]:

                        if "_s_" in tx["vOut"][i]:
                            self.coins += 1
                        else:
                            out = tx["vOut"][i]
                            if self.skip_opreturn and out["nType"] in (3, 8):
                                self.op_return += 1
                                continue
                            self.coins += 1
                            pointer = (block["height"] << 39) + (q << 20) + (1 << 19) + i
                            try:
                                address = b"".join((bytes([out["nType"]]), out["addressHash"]))
                            except:
                                address = b"".join((bytes([out["nType"]]), out["scriptPubKey"]))
                            self.utxo.set(b"".join((tx["txId"], int_to_bytes(i))), pointer, out["value"], address)

            c = 0
            ti = 0
            stxo, missed = dict(), set()
            for q in block["rawTx"]:
                tx = block["rawTx"][q]
                if not tx["coinbase"]:
                    if self.utxo:
                        for i in tx["vIn"]:
                            ti += 1
                            self.destroyed_coins += 1
                            inp = tx["vIn"][i]
                            outpoint = b"".join((inp["txId"], int_to_bytes(inp["vOut"])))
                            tx["vIn"][i]["outpoint"] = outpoint
                            try:
                                tx["vIn"][i]["coin"] = inp["_a_"]
                                c += 1
                                self.preload_cached_annihilated += 1
                                self.preload_cached_total += 1
                            except:
                                try:
                                    tx["vIn"][i]["coin"] = inp["_c_"]
                                    c += 1
                                    self.preload_cached_total += 1
                                    self.preload_cached += 1
                                    self.utxo.get(outpoint)
                                except:
                                    r = self.utxo.get(outpoint)
                                    if r:
                                        tx["vIn"][i]["coin"] = r
                                        c += 1
                                    else:
                                        missed.add((outpoint, (block["height"] << 39) + (q << 20) + (1 << 19) + i, q, i))

            if missed:
                t2 = time.time()
                await self.utxo.load_utxo()
                t2 =time.time() - t2
                self.batch_load_utxo += t2
                for o, s, q, i in missed:
                    block["rawTx"][q]["vIn"][i]["coin"] = self.utxo.get_loaded(o)
                    c += 1

                if c != ti and not self.cache_loading:
                    self.log.critical("utxo get failed " + rh2s(block["hash"]))
                    raise Exception("utxo get failed ")

            self.total_received_tx += len(block["rawTx"])
            self.total_received_tx_last += len(block["rawTx"])
            self.batch_parsing += (time.time() - t) - t2
        except Exception as err:
            self.log.critical("new block error %s " % err)
            self.log.critical(str(traceback.format_exc()))
        finally:
            pass

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
                        if len(batch) >= self.rpc_batch_limit:
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
                c = 0
                self.tx_in_process.add(tx["txId"])
                if not tx["coinbase"]:
                    if block_height is not None:
                        await self.wait_block_dependences(tx)
                    if self.utxo:
                        stxo, missed = dict(), set()
                        for i in tx["vIn"]:
                            self.destroyed_coins += 1
                            inp = tx["vIn"][i]
                            outpoint = b"".join((inp["txId"], int_to_bytes(inp["vOut"])))
                            tx["vIn"][i]["outpoint"] = outpoint
                            try:
                                tx["vIn"][i]["coin"] = inp["_a_"]
                                c += 1
                                self.preload_cached_anigilated += 1
                            except:
                                try:
                                    tx["vIn"][i]["coin"] = inp["_c_"]
                                    c += 1
                                    self.preload_cached += 1
                                    try:
                                        self.utxo.get(outpoint)
                                    except:
                                        self.utxo.deleted.add(outpoint)
                                except:
                                    r = self.utxo.get(outpoint)
                                    if r:
                                        tx["vIn"][i]["coin"]  = r
                                        c += 1
                                    else:
                                        missed.add((outpoint,(block_height << 39)+(block_index << 20)+(1 << 19) + i))

                        if missed:
                            await self.utxo.load_utxo()
                            for o, s, i in missed:
                                tx["vIn"][i]["coin"] = self.utxo.get_loaded(o)
                                c += 1


                        if c != len(tx["vIn"]) and not self.cache_loading:
                            self.log.critical("utxo get failed " + rh2s(tx["txId"]))
                            raise Exception("utxo get failed ")

                if self.tx_handler and  not self.cache_loading:
                    await self.tx_handler(tx, block_time, block_height, block_index)

                if self.utxo:
                    for i in tx["vOut"]:
                        self.coins += 1
                        if "_s_" in tx["vOut"][i]:
                            self.preload_cached_total += 1
                        else:
                            out = tx["vOut"][i]
                            if self.skip_opreturn and out["nType"] in (3, 8):
                                continue
                            pointer = (block_height << 39)+(block_index << 20)+(1 << 19) + i
                            try:
                                address = b"".join((bytes([out["nType"]]), out["addressHash"]))

                            except:
                                address = b"".join((bytes([out["nType"]]), out["scriptPubKey"]))
                            self.utxo.set(b"".join((tx["txId"], int_to_bytes(i))), pointer, out["value"], address)

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


    async def get_stxo(self, tx, block_height, block_index):
        stxo, missed = set(), set()
        block_height = 0 if block_height is None else block_height
        block_index = 0 if block_index is None else block_index

        for i in tx["vIn"]:
            inp = tx["vIn"][i]
            outpoint = b"".join((inp["txId"], int_to_bytes(inp["vOut"])))
            r = self.utxo.get(outpoint)
            stxo.add(r) if r else missed.add((outpoint, (block_height << 39)+(block_index << 20)+(1 << 19) + i))

        if missed:
            await self.utxo.load_utxo()
            [stxo.add(self.utxo.get_loaded(o, block_height)) for o, s in missed]

        if len(stxo) != len(tx["vIn"]) and not self.cache_loading:
            self.log.critical("utxo get failed " + rh2s(tx["txId"]))
            self.log.critical(str(stxo))
            raise Exception("utxo get failed ")
        return stxo



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




