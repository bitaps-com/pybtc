import asyncio
import os
from multiprocessing import Process
from concurrent.futures import ThreadPoolExecutor
from setproctitle import setproctitle
import logging
import signal
import sys

class BlockLoader:
    def __init__(self, parent, workers=4):
        self.worker = list()
        self.log = parent.log
        self.loop = parent.loop
        self.loop.set_default_executor(ThreadPoolExecutor(workers * 2))
        [self.loop.create_task(self.start_worker(i)) for i in range(workers)]

    async def start_worker(self,index):
        self.log.warning('Start block loader worker %s' % index)
        # prepare pipes for communications
        in_reader, in_writer = os.pipe()
        out_reader, out_writer = os.pipe()
        in_reader, out_reader  = os.fdopen(in_reader,'rb'), os.fdopen(out_reader,'rb')
        in_writer, out_writer  = os.fdopen(in_writer,'wb'), os.fdopen(out_writer,'wb')

        # create new process
        worker = Process(target=Worker, args=(index, in_reader, in_writer, out_reader, out_writer))
        worker.start()
        in_reader.close()
        out_writer.close()
        # get stream reader
        worker.reader = await self.get_pipe_reader(out_reader)
        worker.writer = in_writer
        worker.name   = str(index)
        self.worker[index] =  worker
        # start message loop
        self.loop.create_task(self.message_loop(self.worker[index]))
        # wait if process crash
        await self.loop.run_in_executor(None, worker.join)
        del self.worker[index]
        self.log.warning('Block loader worker %s is stopped' % index)


    async def get_pipe_reader(self, fd_reader):
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        try:
            await self.loop.connect_read_pipe(lambda: protocol, fd_reader)
        except:
            return None
        return reader

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

    def pipe_sent_msg(self, writer, msg_type, msg):
        msg_type = msg_type[:20].ljust(20)
        msg = msg_type + msg
        msg = b''.join((b'ME', len(msg).to_bytes(4, byteorder='little'), msg))
        writer.write(msg)
        writer.flush()



    async def message_loop(self, worker):
        while True:
            msg_type, msg = await self.pipe_get_msg(worker.reader)
            if msg_type ==  b'pipe_read_error':
                if not worker.is_alive():
                    return
                continue

            if msg_type == b'result':
                msg
                continue


    # def disconnect(self,ip):
    #     """ Disconnect peer """
    #     p = self.out_connection_pool[self.outgoing_connection[ip]["pool"]]
    #     pipe_sent_msg(p.writer, b'disconnect', ip.encode())





class Worker:

    def __init__(self, name , in_reader, in_writer, out_reader, out_writer):
        setproctitle('Block loader: worker %s' % name)
        self.name = name
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
        signal.signal(signal.SIGTERM, self.terminate)
        self.loop.create_task(self.message_loop())
        self.loop.run_forever()


    def terminate(self,a,b):
        sys.exit(0)

    async def get_pipe_reader(self, fd_reader):
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        try:
            await self.loop.connect_read_pipe(lambda: protocol, fd_reader)
        except:
            return None
        return reader

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

    def pipe_sent_msg(self, writer, msg_type, msg):
        msg_type = msg_type[:20].ljust(20)
        msg = msg_type + msg
        msg = b''.join((b'ME', len(msg).to_bytes(4, byteorder='little'), msg))
        writer.write(msg)
        writer.flush()



    async def message_loop(self, worker):
        while True:
            msg_type, msg = await self.pipe_get_msg(worker.reader)
            if msg_type ==  b'pipe_read_error':
                if not worker.is_alive():
                    return
                continue

            if msg_type == b'result':
                msg
                continue


