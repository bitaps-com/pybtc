from pybtc.functions.tools import bytes_to_int
from pybtc.functions.tools import int_to_bytes
from pybtc.connector.utils import decode_block_tx
from pybtc import MRU
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


try:
    import asyncpg
except:
    pass

try:
    from setproctitle import setproctitle
except:
    raise Exception("required module setproctitle")

try:
    import aiojsonrpc
except:
    raise Exception("required module aiojsonrpc")



class BlockLoader:
    def __init__(self, parent, workers=4, dsn = None):
        self.worker_limit = workers
        self.worker = dict()
        self.worker_tasks = list()
        self.worker_busy = dict()
        self.parent = parent
        self.last_batch_size = 0
        self.reached_height = 0
        self.loading_task = None
        self.dsn = dsn
        self.log = parent.log
        self.loop = parent.loop
        self.rpc_url = parent.rpc_url
        self.rpc_timeout = parent.rpc_timeout
        self.rpc_batch_limit = parent.rpc_batch_limit
        self.loop.set_default_executor(ThreadPoolExecutor(workers * 2))
        self.watchdog_task = self.loop.create_task(self.watchdog())


    async def watchdog(self):
        while True:
            try:
                if self.loading_task is None or self.loading_task.done():
                    if self.parent.deep_synchronization and not self.parent.cache_loading:
                        self.loading_task = self.loop.create_task(self.loading())
                else:
                    # clear unused cache
                    if self.parent.block_preload._store:
                        if next(iter(self.parent.block_preload._store)) <= self.parent.last_block_height:
                            for i in range(next(iter(self.parent.block_preload._store)),
                                           self.parent.last_block_height + 1):

                                try: self.parent.block_preload.remove(i)
                                except: pass

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
            target_height = self.parent.node_last_block - self.parent.deep_sync_limit
            new_requests = 0
            if self.parent.block_preload._store_size < self.parent.block_preload_cache_limit:
                try:
                    for i in self.worker_busy:
                        if not self.worker_busy[i]:
                            self.worker_busy[i] = True
                            if self.height <= self.parent.last_block_height:
                                self.height = self.parent.last_block_height + 1
                            await self.pipe_sent_msg(self.worker[i].writer, b'rpc_batch_limit',
                                                     int_to_bytes(self.rpc_batch_limit))
                            await self.pipe_sent_msg(self.worker[i].writer, b'get', int_to_bytes(self.height))
                            self.height += self.rpc_batch_limit
                            new_requests += 1
                    if not new_requests:
                        await asyncio.sleep(1)
                        continue
                    if self.last_batch_size < self.parent.block_preload_batch_size_limit:
                        self.rpc_batch_limit += 40
                    elif self.last_batch_size >  self.parent.block_preload_batch_size_limit and self.rpc_batch_limit > 60:
                        self.rpc_batch_limit -= 40
                except asyncio.CancelledError:
                    self.log.info("Loading task terminated")
                    [self.worker[p].terminate() for p in self.worker]
                    for p in self.worker_busy: self.worker_busy[p] = False
                    return
                except Exception as err:
                    self.log.error("Loading task  error %s " % err)
            else:
                await  asyncio.sleep(1)


        self.watchdog_task.cancel()
        if self.parent.block_preload._store:
            while next(reversed(self.parent.block_preload._store)) < target_height:
                await asyncio.sleep(1)
            self.log.info("block loader reached target block %s" % target_height)
            self.log.debug("    Cache first block %s; "
                           "cache last block %s;" % (next(iter(self.parent.block_preload._store)),
                                                     next(reversed(self.parent.block_preload._store))))

        [self.worker[p].terminate() for p in self.worker]
        for p in self.worker_busy: self.worker_busy[p] = False


    async def start_worker(self,index):
        self.log.info('Start block loader worker %s' % index)
        # prepare pipes for communications
        in_reader, in_writer = os.pipe()
        out_reader, out_writer = os.pipe()
        in_reader, out_reader  = os.fdopen(in_reader,'rb'), os.fdopen(out_reader,'rb')
        in_writer, out_writer  = os.fdopen(in_writer,'wb'), os.fdopen(out_writer,'wb')

        # create new process
        worker = Process(target=Worker, args=(index, in_reader, in_writer, out_reader, out_writer,
                                              self.rpc_url, self.rpc_timeout, self.rpc_batch_limit,
                                              self.dsn, self.parent.app_proc_title))
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

    def __init__(self, name , in_reader, in_writer, out_reader, out_writer,
                 rpc_url, rpc_timeout, rpc_batch_limit, dsn, app_proc_title):
        setproctitle('%s: blocks preload worker %s' % (app_proc_title, name))
        self.rpc_url = rpc_url
        self.rpc_timeout = rpc_timeout
        self.rpc_batch_limit = rpc_batch_limit
        self.name = name
        self.dsn = dsn
        self.db = None
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
        self.destroyed_coins = MRU(1000000)
        signal.signal(signal.SIGTERM, self.terminate)
        self.msg_loop = self.loop.create_task(self.message_loop())
        self.loop.run_forever()

    async def load_blocks(self, height, limit):
        start_height = height
        try:
            x = None
            blocks = dict()
            missed =deque()
            t = 0
            e = height + limit
            limit = 40
            while height < e:

                batch, h_list = list(), list()
                while len(batch) < limit and height < e:
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
                        for z in block["rawTx"]:
                            for i in block["rawTx"][z]["vOut"]:
                                o = b"".join((block["rawTx"][z]["txId"], int_to_bytes(i)))
                                pointer = (x << 39)+(z << 20)+(1 << 19) + i
                                try:
                                    address = b"".join((bytes([block["rawTx"][z]["vOut"][i]["nType"]]),
                                                               block["rawTx"][z]["vOut"][i]["addressHash"]))
                                except:
                                    address = b"".join((bytes([block["rawTx"][z]["vOut"][i]["nType"]]),
                                                        block["rawTx"][z]["vOut"][i]["scriptPubKey"]))
                                self.coins[o] = (pointer, block["rawTx"][z]["vOut"][i]["value"], address)


                            if not block["rawTx"][z]["coinbase"]:
                                for i  in block["rawTx"][z]["vIn"]:
                                    inp = block["rawTx"][z]["vIn"][i]
                                    outpoint = b"".join((inp["txId"], int_to_bytes(inp["vOut"])))
                                    try:
                                       r = self.coins.delete(outpoint)
                                       if r[0] >> 39 >= start_height and r[0] >> 39 < height:
                                           block["rawTx"][z]["vIn"][i]["_a_"] = r
                                       else:
                                           block["rawTx"][z]["vIn"][i]["_c_"] = r
                                       t += 1
                                       self.destroyed_coins[r[0]] = True
                                       assert r is not None
                                    except:
                                        if self.dsn:
                                            missed.append(outpoint)

                        blocks[x] = block



            m = 0
            n = 0
            if missed and self.dsn:
               if self.dsn:
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
                   for block in  blocks:
                       for z in blocks[block]["rawTx"]:
                           if not blocks[block]["rawTx"][z]["coinbase"]:
                               for i in blocks[block]["rawTx"][z]["vIn"]:
                                   inp = blocks[block]["rawTx"][z]["vIn"][i]
                                   outpoint = b"".join((inp["txId"], int_to_bytes(inp["vOut"])))
                                   try:
                                       blocks[block]["rawTx"][z]["vIn"][i]["_l_"] = p[outpoint]
                                       assert p[outpoint] is not None
                                       t += 1
                                       n += 1
                                   except:
                                       pass
            if blocks:
                blocks[x]["checkpoint"] = x
            for x in blocks:
                for y in blocks[x]["rawTx"]:
                    for i in blocks[x]["rawTx"][y]["vOut"]:
                        try:
                            r = self.destroyed_coins.delete((x<<39)+(y<<20)+(1<<19)+i)
                            blocks[x]["rawTx"][y]["vOut"][i]["_s_"] = r
                            assert r is not None
                        except: pass

                blocks[x] = pickle.dumps(blocks[x])
            await self.pipe_sent_msg(b'result', pickle.dumps(blocks))
        except Exception as err:
            self.log.debug("load blocks error: %s" % str(err))
            await self.pipe_sent_msg(b'result', pickle.dumps([]))
            await self.pipe_sent_msg(b'failed', pickle.dumps(start_height))


    async def message_loop(self):
        try:
            self.rpc = aiojsonrpc.rpc(self.rpc_url, self.loop, timeout=self.rpc_timeout)
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

        except:
            pass


    def terminate(self,a,b):
        self.loop.create_task(self.terminate_coroutine())


    async def terminate_coroutine(self):
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


