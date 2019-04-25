from pybtc.functions.tools import rh2s
from pybtc.functions.tools import var_int_to_int
from pybtc.functions.tools import read_var_int
from pybtc.functions.tools import bytes_from_hex
from pybtc.transaction import Transaction
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
                 mempool_tx_list=None,
                 tx_handler=None, orphan_handler=None,
                 before_block_handler=None, block_handler=None, after_block_handler=None,
                 block_timeout=30,
                 deep_sync_limit=20, backlog=0, mempool_tx=True,
                 rpc_batch_limit=20, rpc_threads_limit=100, rpc_timeout=100,
                 preload=False):
        self.loop = asyncio.get_event_loop()

        # settings
        self.log = logger
        self.rpc_url = node_rpc_url
        self.zmq_url = node_zerromq_url
        self.orphan_handler = orphan_handler
        self.block_timeout = block_timeout
        self.tx_handler = tx_handler
        self.before_block_handler = before_block_handler
        self.block_handler = block_handler
        self.after_block_handler = after_block_handler
        self.deep_sync_limit = deep_sync_limit
        self.backlog = backlog
        self.mempool_tx = mempool_tx
        self.chain_tail = list(chain_tail) if chain_tail else []
        self.mempool_tx_list = list(mempool_tx_list) if mempool_tx_list else []
        self.rpc_timeout = rpc_timeout
        self.batch_limit = rpc_batch_limit

        # state and stats
        self.node_last_block = None
        self.last_block_height = int(last_block_height) if int(last_block_height) else 0
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
        self.blocks_processing_time = 0
        self.total_received_tx_time = 0

        # cache and system
        self.preload = preload
        self.block_preload = Cache(max_size=50000)
        self.block_hashes_preload = Cache(max_size=50000)
        self.tx_cache = Cache(max_size=50000)
        self.block_cache = Cache(max_size=10000)

        self.block_txs_request = None

        self.connected = asyncio.Future()
        self.await_tx_list = list()
        self.missed_tx_list = list()
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
                self.log.warning("%s blocks before synchronization synchronized")
                if d > self.deep_sync_limit:
                    self.log.warning("Deep synchronization mode")
                    self.deep_synchronization = True
            break

        [self.tx_cache.set(row, True) for row in self.mempool_tx_list]
        h = self.last_block_height
        if h < len(self.chain_tail):
            raise Exception("Chain tail len not match last block height")
        for row in reversed(self.chain_tail):
            self.block_cache.set(row, h)
            h -= 1

        self.tasks.append(self.loop.create_task(self.zeromq_handler()))
        self.tasks.append(self.loop.create_task(self.watchdog()))
        self.connected.set_result(True)
        if self.preload:
            self.loop.create_task(self.preload_block())
            self.loop.create_task(self.preload_block_hashes())
        self.loop.create_task(self.get_next_block())

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
                            hash = body.hex()
                            self.log.warning("New block %s" % hash)
                            self.loop.create_task(self._get_block_by_hash(hash))
                        elif topic == b"rawtx":
                            self.last_zmq_msg = int(time.time())
                            if self.deep_synchronization:
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
        if not self.active:
            return
        if not self.get_next_block_mutex.done():
            await self.get_next_block_mutex
        try:
            self.get_next_block_mutex = asyncio.Future()

            if self.node_last_block <= self.last_block_height + self.backlog:
                d = await self.rpc.getblockcount()
                if d == self.node_last_block:
                    self.log.info("blockchain is synchronized backlog %s" % self.backlog)
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
            h = await self.rpc.getblockhash(self.last_block_height + 1)
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
                block = await self.rpc.getblock(hash)
            self.loop.create_task(self._new_block(block))
        except Exception:
            self.log.error("get block by hash %s FAILED" % hash)

    async def _new_block(self, block):
        if not self.active or not self.active_block.done() or self.last_block_height >= block["height"]:
            return
        self.active_block = asyncio.Future()
        self.block_dependency_tx = 0
        bin_block_hash = bytes_from_hex(block["hash"])
        bin_prev_block_hash = block["previousblockhash"] if "previousblockhash" in block else None
        block_height = int(block["height"])
        self.log.debug("New block %s %s" % (block_height, block["hash"]))
        bt = tm()
        bpt = 0
        try:
            # blockchain position check
            if self.block_cache.get(bin_block_hash) is not None:
                self.log.debug("duplicated block  %s" % block["hash"])
                return
            if self.block_cache.get(bin_prev_block_hash) is None and self.last_block_height:
                self.log.critical("Connector panic! Node out of sync no parent block in chain tail %s" % bin_prev_block_hash)
                return

            if self.last_block_height + 1 != block_height:
                if self.orphan_handler:
                    tq = tm()
                    await self.orphan_handler(self.last_block_height)
                    self.log.info("orphan handler  %s [%s]" % (self.last_block_height, tm(tq)))
                self.block_cache.pop_last()
                self.last_block_height -= 1
                return
            # add all block transactions

            missed = set()
            for h in block["tx"]:
                if self.tx_cache.get(h) is None:
                    missed.add(h)

            if self.before_block_handler:
                q = time.time()
                await self.before_block_handler(block)
                bpt = time.time() - q
                self.blocks_processing_time += bpt

            self.log.info("Transactions missed %s" % len(missed))
            cq = tm()
            if missed:
                self.log.debug("Request missed transactions")
                self.missed_tx_list = set(missed)
                self.await_tx_list = missed
                self.await_tx_future = dict()
                for i in missed:
                    self.await_tx_future[i] = asyncio.Future()
                self.block_txs_request = asyncio.Future()
                if self.deep_synchronization:
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
            self.total_received_tx_time += tm(cq)
            rate = round(self.total_received_tx/self.total_received_tx_time)
            self.log.info("Transactions received: %s [%s] rate tx/s ->> %s <<" % (tx_count, tm(cq), rate))

            if self.block_handler:
                q = time.time()
                await self.block_handler(block)
                self.blocks_processing_time += time.time() - q
                bpt += time.time() - q
                # insert new block
            self.block_cache.set(block["hash"], block["height"])
            self.last_block_height = block["height"]


            # after block added handler
            if self.after_block_handler:
                q = time.time()
                try:
                    await self.after_block_handler(block)
                except:
                    pass
                self.blocks_processing_time += time.time() - q
                bpt += time.time() - q
                self.blocks_processed_count += 1

            [self.tx_cache.pop(h) for h in block["tx"]]
        except Exception as err:
            if self.await_tx_list:
                self.await_tx_list = set()
            self.log.error(str(traceback.format_exc()))
            self.log.error("new block error %s" % str(err))
        finally:
            self.active_block.set_result(True)
            self.log.info("> %s < block [%s tx/ %s size] (dp %s) processing time %s cache [%s/%s]" %
                          (block["height"],
                           len(block["tx"]),
                           block["size"] / 1000000,
                           self.block_dependency_tx,
                           tm(bt),
                           len(self.block_hashes_preload._store),
                           len(self.block_preload._store)))
            if self.node_last_block > self.last_block_height:
                self.loop.create_task(self.get_next_block())


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

                    self.log.info("block downloaded %s decoded %s " % (round(dt, 4), round(qt, 4)))
                    for index, tx in enumerate(block):
                        try:
                            self.missed_tx_list.remove(rh2s(block[tx]["txId"]))
                            self.loop.create_task(self._new_transaction(block[tx], block_time, block_height, index))
                        except:
                            pass
            except Exception as err:
                self.log.error("_get_missed exception %s " % str(err))
                self.log.error(str(traceback.format_exc()))
                self.await_tx_list = set()
                self.block_txs_request.cancel()

        elif self.get_missed_tx_threads <= self.get_missed_tx_threads_limit:
            self.get_missed_tx_threads += 1
            # start more threads
            if len(self.missed_tx_list) > 1:
                self.loop.create_task(self._get_missed(False, block_time, block_height))
            while True:
                if not self.missed_tx_list:
                    break
                try:
                    batch = list()
                    while self.missed_tx_list:
                        batch.append(["getrawtransaction", self.missed_tx_list.pop()])
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
                    self.await_tx_list = set()
                    self.block_txs_request.cancel()
            self.get_missed_tx_threads -= 1


    async def _new_transaction(self, tx, block_time = None, block_height = None, block_index = None):
        tx_hash = rh2s(tx["txId"])
        if tx_hash in self.tx_in_process or self.tx_cache.get(tx["txId"]):
            return
        try:
            ft = self.await_tx_future if block_height is not None else None
            self.tx_in_process.add(tx_hash)

            if self.tx_handler:
                await self.tx_handler(tx, ft, block_time, block_height, block_index)

            self.tx_cache.set(tx_hash, True)
            try:
                self.await_tx_list.remove(tx_hash)
                if not self.await_tx_future[tx_hash].done():
                    self.await_tx_future[tx_hash].set_result(True)
                if not self.await_tx_list:
                    self.block_txs_request.set_result(True)
            except:
                pass
        except DependsTransaction as err:
            self.block_dependency_tx += 1
            self.loop.create_task(self.wait_tx_then_add(err.raw_tx_hash, tx))
        except Exception as err:
            if tx_hash in self.await_tx_list:
                self.await_tx_list = set()
                self.block_txs_request.cancel()
                for i in self.await_tx_future:
                    if not self.await_tx_future[i].done():
                        self.await_tx_future[i].cancel()
            self.log.debug("new transaction error %s " % err)
            self.log.debug(str(traceback.format_exc()))
        finally:
            self.tx_in_process.remove(tx_hash)





    async def wait_tx_then_add(self, raw_tx_hash, tx):
        tx_hash = rh2s(tx["hash"])
        try:
            if not self.await_tx_future[raw_tx_hash].done():
                await self.await_tx_future[raw_tx_hash]
            self.loop.create_task(self._new_transaction(tx))
        except:
            self.tx_in_process.remove(tx_hash)





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

