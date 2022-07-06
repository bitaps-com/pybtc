import configparser
import argparse
import asyncio
import sys
import signal
import traceback
import logging
import colorlog
import uvloop
from  pybtc.connector import Connector

asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())



class App:
    def __init__(self, loop, logger, config):
        self.loop = loop
        self.log = logger
        self.connector = None
        self.config = config
        self.log.info("Test server init ...")
        signal.signal(signal.SIGINT, self.terminate)
        signal.signal(signal.SIGTERM, self.terminate)
        asyncio.ensure_future(self.start(config), loop=self.loop)

    async def start(self, config):
        # init database
        try:
            zeromq = config['BITCOIND']["zeromq"]
            rpc = config['BITCOIND']["rpc"]

            self.connector = Connector(rpc, zeromq, self.log,
                                        before_block_handler = self.before_block_handler)
            await self.connector.connected

        except Exception as err:
            self.log.error("Start failed")
            self.log.error(str(traceback.format_exc()))


    async def orphan_block_handler(self, orphan_hash):
        self.log.warning("handler remove orphan %s" % orphan_hash)

    async def before_block_handler(self, data):
        self.log.warning("handler new block %s" % str(data["hash"]))


    async def new_transaction_handler(self, data, ft, a,b,c):
        assert data["rawTx"] == data.serialize(hex=False)


    def _exc(self, a, b, c):
        return

    def terminate(self, a, b):
        self.loop.create_task(self.terminate_coroutine())

    async def terminate_coroutine(self):
        sys.excepthook = self._exc
        self.log.error('Stop request received')
        if self.connector:
            self.log.warning("Stop node connector")
            await self.connector.stop()
        self.log.info("Test server stopped")
        self.loop.stop()


def init(loop, argv):
    parser = argparse.ArgumentParser(description="Test node connector ...")
    args = parser.parse_args()
    config_file = "test.conf"
    log_level = logging.INFO
    logger = colorlog.getLogger('cn')
    config = configparser.ConfigParser()
    config.read(config_file)

    ch = logging.StreamHandler()
    ch.setLevel(log_level)
    formatter = colorlog.ColoredFormatter('%(log_color)s%(asctime)s %(levelname)s: %(message)s (%(module)s:%(lineno)d)')
    ch.setFormatter(formatter)
    logger.addHandler(ch)
    logger.setLevel(log_level)
    logger.info("Start")
    loop = asyncio.get_event_loop()
    app = App(loop, logger, config)
    return app


if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    app = init(loop, sys.argv[1:])
    loop.run_forever()
    pending = asyncio.Task.all_tasks()
    loop.run_until_complete(asyncio.gather(*pending))
    loop.close()


