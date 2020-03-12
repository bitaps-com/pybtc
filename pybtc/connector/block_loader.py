import asyncio
import os
from multiprocessing import Process
from concurrent.futures import ThreadPoolExecutor
import logging
import signal
import sys
import traceback
from collections import deque
import pickle
import json
import concurrent

try:
    import asyncpg
except:
    pass

try:
    from setproctitle import setproctitle
except:
    pass

try:
    import aiojsonrpc
except:
    pass

from pybtc.functions.tools import bytes_to_int
from pybtc.functions.tools import int_to_bytes
from pybtc.functions.block import merkle_tree, merkle_proof
from pybtc.connector.utils import decode_block_tx
from pybtc import MRU, parse_script, rh2s, MINER_COINBASE_TAG, MINER_PAYOUT_TAG, hash_to_address






class BlockLoader:
    def __init__(self, parent, workers=4, dsn = None):
        self.worker_limit = workers
        self.worker = dict()
        self.worker_tasks = list()
        self.worker_busy = dict()
        self.parent = parent
        self.last_batch_size = 0
        self.loading_completed = False
        self.height = 0
        self.reached_height = 0
        self.loading_task = None
        self.dsn = dsn
        self.log = parent.log
        self.loop = parent.loop
        self.rpc_url = parent.rpc_url
        self.rpc_timeout = parent.rpc_timeout
        self.rpc_batch_limit = parent.rpc_batch_limit
        self.loop.set_default_executor(ThreadPoolExecutor(workers * 2))
        self.loading_task = self.loop.create_task(self.loading())


    async def watchdog(self):
        while self.parent.deep_synchronization:
            try:
                # clear unused cache
                if self.parent.block_preload._store:
                    if next(iter(self.parent.block_preload._store)) <= self.parent.last_block_height:
                        for i in range(next(iter(self.parent.block_preload._store)),
                                       self.parent.last_block_height + 1):
                            try:
                                self.parent.block_preload.remove(i)
                            except:
                                pass

            except asyncio.CancelledError:
                self.log.info("block loader watchdog stopped")
                break
            except Exception as err:
                self.log.error(str(traceback.format_exc()))
                self.log.error("watchdog error %s " % err)

            await asyncio.sleep(10)


    async def loading(self):
        self.rpc_batch_limit = 30
        self.worker_tasks = [self.loop.create_task(self.start_worker(i)) for i in range(self.worker_limit)]
        target_height = self.parent.node_last_block - self.parent.deep_sync_limit
        self.height = self.parent.last_block_height + 1

        while self.height < target_height:
            print("self.rpc_batch_limit", self.rpc_batch_limit)
            await  asyncio.sleep(1)
            target_height = self.parent.node_last_block - self.parent.deep_sync_limit

            if self.parent.block_preload._store_size >= self.parent.block_preload_cache_limit:
                continue

            try:
                n = False
                for i in self.worker_busy:
                    if self.height < target_height:
                        if not self.worker_busy[i]:
                            self.worker_busy[i] = True
                            n = True
                            if self.height <= self.parent.last_block_height:
                                self.height = self.parent.last_block_height + 1
                            await self.pipe_sent_msg(self.worker[i].writer, b'rpc_batch_limit',
                                                     int_to_bytes(self.rpc_batch_limit))
                            await self.pipe_sent_msg(self.worker[i].writer, b'target_height',
                                                     int_to_bytes(target_height))
                            await self.pipe_sent_msg(self.worker[i].writer, b'get', int_to_bytes(self.height))
                            self.height += self.rpc_batch_limit
                            if self.height > target_height:
                                self.height = target_height
                if n: continue

                print("self.last_batch_size", self.last_batch_size, self.parent.block_preload_batch_size_limit)
                if self.last_batch_size < self.parent.block_preload_batch_size_limit:
                    self.rpc_batch_limit += 40
                elif self.last_batch_size >  self.parent.block_preload_batch_size_limit and \
                        self.rpc_batch_limit > 80:
                    self.rpc_batch_limit -= 40

                if self.parent.block_preload._store:
                    if next(iter(self.parent.block_preload._store)) <= self.parent.last_block_height:
                        for i in range(next(iter(self.parent.block_preload._store)),
                                       self.parent.last_block_height + 1):
                            try:
                                self.parent.block_preload.remove(i)
                            except:
                                pass

            except asyncio.CancelledError:
                self.log.info("Loading task terminated")
                [self.worker[p].terminate() for p in self.worker]
                for p in self.worker_busy: self.worker_busy[p] = False
                return

            except Exception as err:
                self.log.error("Loading task  error %s " % err)


        if self.parent.block_preload._store:
            while next(reversed(self.parent.block_preload._store)) < target_height:
                await asyncio.sleep(1)
            self.log.info("block loader reached target block %s" % target_height)
            self.log.debug("    Cache first block %s; "
                           "cache last block %s;" % (next(iter(self.parent.block_preload._store)),
                                                     next(reversed(self.parent.block_preload._store))))
        active = True
        while active:
            active = False
            for i in self.worker_busy:
                if self.worker_busy[i]: active = True
            await asyncio.sleep(1)

        [self.worker[p].terminate() for p in self.worker]
        for p in self.worker_busy: self.worker_busy[p] = False

    def restart(self):
        self.loading_task.cancel()
        self.loading_task = self.loop.create_task(self.loading())


    async def start_worker(self,index):
        self.log.info('Start block loader worker %s' % index)
        # prepare pipes for communications
        in_reader, in_writer = os.pipe()
        out_reader, out_writer = os.pipe()
        in_reader, out_reader  = os.fdopen(in_reader,'rb'), os.fdopen(out_reader,'rb')
        in_writer, out_writer  = os.fdopen(in_writer,'wb'), os.fdopen(out_writer,'wb')

        # create new process
        worker = Process(target=Worker, args=(index,
                                              in_reader,
                                              in_writer,
                                              out_reader,
                                              out_writer,
                                              self.rpc_url,
                                              self.rpc_timeout,
                                              self.rpc_batch_limit,
                                              self.dsn,
                                              self.parent.app_proc_title,
                                              self.parent.utxo_data,
                                              self.parent.option_tx_map,
                                              self.parent.option_block_filters,
                                              self.parent.option_merkle_proof,
                                              self.parent.option_analytica))
        worker.start()
        in_reader.close()
        out_writer.close()

        # get stream reader
        worker.reader = await self.get_pipe_reader(out_reader)
        worker.writer = await self.get_pipe_writer(in_writer)
        worker.name   = str(index)
        self.worker[index] =  worker
        self.worker_busy[index] =  False

        # start message loop
        self.loop.create_task(self.message_loop(index))

        # wait if process crash
        await self.loop.run_in_executor(None, worker.join)
        del self.worker[index]
        self.log.info('Block loader worker %s is stopped' % index)


    async def get_pipe_reader(self, fd_reader):
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        try:
            await self.loop.connect_read_pipe(lambda: protocol, fd_reader)
        except:
            return None
        return reader


    async def get_pipe_writer(self, fd_writer):
        try:
            wt, wp = await self.loop.connect_write_pipe(asyncio.streams.FlowControlMixin, fd_writer)
            writer = asyncio.streams.StreamWriter(wt, wp, None, self.loop)
        except:
            return None
        return writer


    async def pipe_get_msg(self, reader):
        while True:
            try:
                msg = await reader.readexactly(1)
                if msg == b'M':
                    msg = await reader.readexactly(1)
                    if msg == b'E':
                        msg = await reader.readexactly(4)
                        c = int.from_bytes(msg, byteorder='little')
                        msg = await reader.readexactly(c)
                        if msg:
                            return msg[:20].rstrip(), msg[20:]
                if not msg:
                    return b'pipe_read_error', b''
            except:
                return b'pipe_read_error', b''


    async def pipe_sent_msg(self, writer, msg_type, msg):
        msg_type = msg_type[:20].ljust(20)
        msg = msg_type + msg
        msg = b''.join((b'ME', len(msg).to_bytes(4, byteorder='little'), msg))
        writer.write(msg)
        await writer.drain()


    async def message_loop(self, index):
        while True:
            msg_type, msg = await self.pipe_get_msg(self.worker[index].reader)
            if msg_type ==  b'pipe_read_error':
                return

            if msg_type == b'result':
                self.worker_busy[index] = False
                blocks = pickle.loads(msg)
                if blocks:
                    self.last_batch_size = len(msg)
                else:
                    self.rpc_batch_limit = 40
                for i in blocks:
                    self.parent.block_preload.set(i, blocks[i])
                if blocks:
                    if self.parent.utxo_data:
                        if  self.parent.sync_utxo.checkpoints:
                            if self.parent.sync_utxo.checkpoints[-1] < i:
                                self.parent.sync_utxo.checkpoints.append(i)
                                self.reached_height = i
                        else:
                            self.parent.sync_utxo.checkpoints.append(i)

            if msg_type == b'failed':
                self.height = bytes_to_int(msg)
                self.log.debug("failed load block %s" % self.height)
                continue


class Worker:

    def __init__(self,
                 name,
                 in_reader,
                 in_writer,
                 out_reader,
                 out_writer,
                 rpc_url,
                 rpc_timeout,
                 rpc_batch_limit,
                 dsn,
                 app_proc_title,
                 utxo_data,
                 option_tx_map,
                 option_block_filters,
                 option_merkle_proof,
                 option_analytica):
        try:
            setproctitle('%s: blocks preload worker %s' % (app_proc_title, name))
        except:
            pass

        self.rpc_url = rpc_url
        self.rpc_timeout = rpc_timeout
        self.rpc_batch_limit = rpc_batch_limit
        self.utxo_data = utxo_data
        self.target_height = 0
        self.name = name
        self.dsn = dsn
        self.db = None
        self.option_tx_map = option_tx_map
        self.option_merkle_proof = option_merkle_proof
        self.option_block_filters = option_block_filters
        self.option_analytica = option_analytica
        in_writer.close()
        out_reader.close()
        policy = asyncio.get_event_loop_policy()
        policy.set_event_loop(policy.new_event_loop())
        self.loop = asyncio.get_event_loop()
        self.log = logging.getLogger("Block loader")
        self.log.setLevel(logging.INFO)
        self.loop.set_default_executor(ThreadPoolExecutor(20))
        self.out_writer = out_writer
        self.in_reader = in_reader
        self.coins = MRU(500000)
        signal.signal(signal.SIGTERM, self.terminate)
        self.msg_loop = self.loop.create_task(self.message_loop())
        self.loop.run_forever()

    async def load_blocks(self, height, limit):
        start_height = height
        start_limit = limit
        self.destroyed_coins = MRU()
        self.coins = MRU()

        try:
            self.rpc = aiojsonrpc.rpc(self.rpc_url, self.loop, timeout=self.rpc_timeout)
            blocks, missed = dict(), deque()
            v, t, limit = height + limit, 0, 40

            while height < v and height <= self.target_height:
                batch, h_list = list(), list()
                while len(batch) < limit and height < v and height <= self.target_height:
                    batch.append(["getblockhash", height])
                    h_list.append(height)
                    height += 1

                result = await self.rpc.batch(batch)

                h, batch = list(), list()
                for lh, r in zip(h_list, result):
                    if r["result"] is not None:
                        batch.append(["getblock", r["result"], 0])
                        h.append(lh)

                result = await self.rpc.batch(batch)

                for x, y in zip(h, result):
                    if y["result"] is not None:
                        block = decode_block_tx(y["result"])
                        block["p2pkMapHash"] = []
                        if self.option_tx_map: block["txMap"], block["stxo"] = deque(), deque()

                        if self.option_block_filters:
                            block["filter"] = set()


                        if self.option_merkle_proof:
                            mt = merkle_tree(block["rawTx"][i]["txId"] for i in block["rawTx"])

                        coinbase = block["rawTx"][0]["vIn"][0]["scriptSig"]
                        block["miner"] = None
                        for tag in MINER_COINBASE_TAG:
                            if coinbase.find(tag) != -1:
                                block["miner"] = json.dumps(MINER_COINBASE_TAG[tag])
                                break
                        else:
                            try:
                                address_hash = block["rawTx"][0]["vOut"][0]["addressHash"]
                                script_hash = False if block["rawTx"][0]["vOut"][0]["nType"] == 1 else True
                                a = hash_to_address(address_hash, script_hash=script_hash)
                                if a in MINER_PAYOUT_TAG:
                                    block["miner"] = json.dumps(MINER_PAYOUT_TAG[a])
                            except:
                                pass


                        if self.utxo_data:
                            # handle outputs
                            for z in block["rawTx"]:
                                if self.option_merkle_proof:
                                    block["rawTx"][z]["merkleProof"] = b''.join(merkle_proof(mt, z, return_hex=False))

                                for i in block["rawTx"][z]["vOut"]:
                                    out= block["rawTx"][z]["vOut"][i]
                                    o = b"".join((block["rawTx"][z]["txId"], int_to_bytes(i)))
                                    pointer = (x << 39)+(z << 20)+(1 << 19) + i
                                    out_type = out["nType"]

                                    try:
                                        if out_type == 2:
                                            block["p2pkMapHash"].append((out["addressHash"], out["scriptPubKey"]))
                                            raise Exception("P2PK")
                                        address = b"".join((bytes([out_type]), out["addressHash"]))
                                    except:
                                        address = b"".join((bytes([out_type]), out["scriptPubKey"]))

                                    if out_type in (0, 1, 2, 5, 6):
                                        if self.option_block_filters:
                                            e = b"".join((bytes([out_type]),
                                                          z.to_bytes(4, byteorder="little"),
                                                          out["addressHash"][:20]))
                                            block["filter"].add(e)

                                        if self.option_tx_map:
                                                block["txMap"].append((pointer, address, out["value"]))

                                    out["_address"] = address
                                    self.coins[o] = (pointer, out["value"], address)


                            # handle inputs
                            for z in block["rawTx"]:
                                if not block["rawTx"][z]["coinbase"]:
                                    for i  in block["rawTx"][z]["vIn"]:
                                        inp = block["rawTx"][z]["vIn"][i]
                                        outpoint = b"".join((inp["txId"], int_to_bytes(inp["vOut"])))
                                        block["rawTx"][z]["vIn"][i]["_outpoint"] = outpoint

                                        try:
                                           r = self.coins.delete(outpoint)
                                           try:
                                               block["rawTx"][z]["vIn"][i]["_a_"] = r
                                               self.destroyed_coins[r[0]] = True
                                               out_type = r[2][0]

                                               if self.option_block_filters:
                                                   if out_type in (0, 1, 5, 6):
                                                       e = b"".join((bytes([out_type]),
                                                                     z.to_bytes(4, byteorder="little"),
                                                                     r[2][1:21]))
                                                       block["filter"].add(e)
                                                   elif out_type == 2:
                                                       a = parse_script(r[2][1:])["addressHash"]
                                                       e = b"".join((bytes([out_type]),
                                                                     z.to_bytes(4, byteorder="little"),
                                                                     a[:20]))
                                                       block["filter"].add(e)

                                               if self.option_tx_map:
                                                   block["txMap"].append(((x<<39)+(z<<20)+i, r[2], r[1]))
                                                   block["stxo"].append((r[0], (x<<39)+(z<<20)+i))

                                               t += 1
                                           except:
                                               print(traceback.format_exc())

                                        except:
                                            if self.dsn:
                                                missed.append(outpoint)

                        blocks[x] = block

            m, n = 0, 0
            if self.utxo_data and missed and self.dsn:
               async with self.db.acquire() as conn:
                   rows = await conn.fetch("SELECT outpoint, "
                                           "       pointer,"
                                           "       address,"
                                           "       amount "
                                           "FROM connector_utxo "
                                           "WHERE outpoint = ANY($1);", missed)
               m += len(rows)

               p = dict()
               for row in rows:
                    p[row["outpoint"]] = (row["pointer"],  row["amount"], row["address"])

               for h in  blocks:
                   for z in blocks[h]["rawTx"]:
                       if not blocks[h]["rawTx"][z]["coinbase"]:
                           for i in blocks[h]["rawTx"][z]["vIn"]:
                               outpoint = blocks[h]["rawTx"][z]["vIn"][i]["_outpoint"]
                               try:
                                   blocks[h]["rawTx"][z]["vIn"][i]["_l_"] = p[outpoint]
                                   try:
                                       out_type = p[outpoint][2][0]
                                       if self.option_block_filters:
                                           if out_type in (0, 1, 5, 6):
                                               e = b"".join((bytes([out_type]),
                                                             z.to_bytes(4, byteorder="little"),
                                                             p[outpoint][2][1:21]))
                                               blocks[h]["filter"].add(e)
                                           elif out_type == 2:
                                               a = parse_script(p[outpoint][2][1:])["addressHash"]
                                               e = b"".join((bytes([out_type]),
                                                             z.to_bytes(4, byteorder="little"),
                                                             a[:20]))
                                               blocks[h]["filter"].add(e)


                                       if self.option_tx_map:
                                           blocks[h]["txMap"].append(((h<<39)+(z<<20)+i,
                                                                      p[outpoint][2], p[outpoint][1]))
                                           blocks[h]["stxo"].append((p[outpoint][0], (h<<39)+(z<<20)+i))

                                       t += 1
                                       n += 1

                                   except:
                                       print(traceback.format_exc())
                               except:
                                   pass

            if self.utxo_data and blocks:
                blocks[x]["checkpoint"] = x

            for x in blocks:
                if self.utxo_data:
                    for y in blocks[x]["rawTx"]:
                        for i in blocks[x]["rawTx"][y]["vOut"]:
                            try:
                                r = self.destroyed_coins.delete((x<<39)+(y<<20)+(1<<19)+i)
                                blocks[x]["rawTx"][y]["vOut"][i]["_s_"] = r
                            except: pass

                if self.option_block_filters:
                    blocks[x]["filter"] = bytearray(b"".join(blocks[x]["filter"]))


                blocks[x] = pickle.dumps(blocks[x])
            await self.pipe_sent_msg(b'result', pickle.dumps(blocks))
        except concurrent.futures.CancelledError:
            pass
        except Exception as err:
            self.log.error("block loader restarting: %s" % err)
            print(traceback.format_exc())
            await asyncio.sleep(1)
            self.loop.create_task(self.load_blocks(start_height, start_limit))
        finally:
            try: await self.rpc.close()
            except: pass




    async def message_loop(self):
        try:
            if self.dsn:
                self.db = await asyncpg.create_pool(dsn=self.dsn, min_size=1, max_size=1)
            self.reader = await self.get_pipe_reader(self.in_reader)
            self.writer = await self.get_pipe_writer(self.out_writer)
            while True:
                msg_type, msg = await self.pipe_get_msg(self.reader)
                if msg_type ==  b'pipe_read_error':
                    return

                if msg_type == b'get':
                    self.loop.create_task(self.load_blocks(bytes_to_int(msg), self.rpc_batch_limit))
                    continue

                if msg_type == b'rpc_batch_limit':
                    self.rpc_batch_limit = bytes_to_int(msg)
                    continue

                if msg_type == b'target_height':
                    self.target_height = bytes_to_int(msg)
                    continue


        except:
            pass


    def terminate(self,a,b):
        self.loop.create_task(self.terminate_coroutine())


    async def terminate_coroutine(self):
        self.log.warning("preload worker terminating ...")
        self.loop.stop()
        pending = asyncio.Task.all_tasks()
        for task in pending:
            task.cancel()
        if pending:
            self.loop.run_until_complete(asyncio.wait(pending))
        self.loop.close()
        sys.exit(0)


    async def get_pipe_reader(self, fd_reader):
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        try:
            await self.loop.connect_read_pipe(lambda: protocol, fd_reader)
        except:
            return None
        return reader


    async def get_pipe_writer(self, fd_writer):
        try:
            wt, wp = await self.loop.connect_write_pipe(asyncio.streams.FlowControlMixin, fd_writer)
            writer = asyncio.streams.StreamWriter(wt, wp, None, self.loop)
        except:
            return None
        return writer


    async def pipe_get_msg(self, reader):
        while True:
            try:
                msg = await reader.readexactly(1)
                if msg == b'M':
                    msg = await reader.readexactly(1)
                    if msg == b'E':
                        msg = await reader.readexactly(4)
                        c = int.from_bytes(msg, byteorder='little')
                        msg = await reader.readexactly(c)
                        if msg:
                            return msg[:20].rstrip(), msg[20:]
                if not msg:
                    return b'pipe_read_error', b''
            except:
                return b'pipe_read_error', b''


    async def pipe_sent_msg(self, msg_type, msg):
        msg_type = msg_type[:20].ljust(20)
        msg = msg_type + msg
        msg = b''.join((b'ME', len(msg).to_bytes(4, byteorder='little'), msg))
        self.writer.write(msg)
        await self.writer.drain()


