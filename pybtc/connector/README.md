## What is a bitcoin node connector?
This is middleware that enabling the delivery of Bitcoin network events to applications from bitcoin node. 
Built-in synchronization algorithm, provides the delivery of events to the application in a stack according
to the chronology.  This module is expandable base for building bitcoin applications.

The logic of the module:
 

            --------------------                                                     ================
           |    Initialization  |                                                   |  orphan app    |
           |                    |                                              ---> |    handler     |
           |  last_block_height |                                             |     |  (remove last  |
           |    chain_tail      |                                             |     |      block)    |
            --------------------                                              |      ================
                      |                                                       |
                      |                                                       |
          ------------------------          ----------------------------      |       ================
         |                        |        |   Zerro mq handlers        | ----|      | New transacion |
         |   Is blockchain        |  Yes   |   wait and process         | ---------> |  app handler   |
         |       synchronized?    | -----> |   new transactions and     |     |       ================
         |                        |   |    |   blocks from bitcoin node | -------
          ------------------------    |     ----------------------------      |  |    ==================
                      |               |                                       |  |   | Before new block |
                      | No            |     ------------------------------    |  |-> |  app handler     |
                      |                --> |  Watchdog monitor last       |   |  |    ==================
                      |--------            |  block on bitcoin blockchain.| --   |           |
                      |        |           |  In case zeromq messages     |      |   ==================
           -----------         |           |  missed/failed it will       | -----   |    New block     |
          |                    |           |  force new blocks to app     |         |    app handler   |
          |                    |            ------------------------------           ==================
      ----------        ===============                                                       |
     | Preload  |      |  Block batch  |                                              ==================
     |  blocks  |----> | cache level 2 |                                             | After new block  |
     | worker 1 | |     ===============                                              |  app handler     |
     | + cache  | |            |  |  |                                                ==================
      ----------  |            |  |  |
          |       |            |  |  |
      ----------  |    ====================== 
     | Preload  | |   |   Block as tx batch  |
     |  blocks  |-|   |      app handler     |
     | worker 2 | |    ======================   
     | + cache  | |               |  |    
      ----------  |               |  |
          |       |       ====================
         ...     -|      |  Flush app cache   |
          |       |      |      handler       |
      ----------  |       ====================
     | Preload  | |                  |
     |  blocks  |-                   | 
     | worker N |            ====================
     | + cache  |           |   Synchronization  |
      ----------            |      completed     |
                            |     app handler    |
                             ====================
                             
## Overview

  The main starting parameters are _last_block_height_ and _chain_tail_.
  - _last_block_height_ this is the last blockchain block on which the application has stopped.
  - _chain_tail_ this is a chain of hashes of the last blockchain blocks.
  
  _chain_tail_ it is recommended to maintain 100 blocks for the miner Bitcoin, which corresponds to coinbase maturirty.
  In other words, this is the number of hashes that guarantee that after this blockchain blockchain can no longer be changed.
  _chain_tail_ used to determine the main chain when reorganizing blocks in the blockchain.
  
  Приложение построенное поверх данного модуля должно реализовать обработчики слудеющих событий:
  
  - **new transaction** (_tx_handler_) called by the connector during normal operation after reaching the synchronization 
  position of the processed application block relative to the blockchain blocks
  
  - **before new block handler** (_before_block_handler_)  called by the connector during normal operation, when received new
  block but block not yet processed by connector and application. This is mean that not all block transactions may already
  received and handled.
  
   
  
  In the connector there are 2 modes of operation.
  
##### Simple mode 
  Конектор скаинурет блокчейн 

## Requirements

  - pyzmq
  - https://github.com/bitaps-com/aiojsonrpc
  - asyncpg (optional) 
  

## Usage

    a = Connector(node_rpc_url, node_zerromq_url, logger,
                  last_block_height=0,
                  chain_tail=None,
                  tx_handler=None,
                  orphan_handler=None,
                  before_block_handler=None,
                  block_handler=None,
                  after_block_handler=None,
                  block_batch_handler=None,
                  flush_app_caches_handler=None,
                  synchronization_completed_handler=None,
                  block_timeout=30,
                  deep_sync_limit=20,
                  backlog=0,
                  mempool_tx=True,
                  rpc_batch_limit=50,
                  rpc_threads_limit=100,
                  rpc_timeout=100,
                  utxo_data=False,
                  utxo_cache_size=1000000,
                  skip_opreturn=True,
                  block_cache_workers= 4,
                  block_preload_cache_limit= 1000 * 1000000,
                  block_preload_batch_size_limit = 200000000,
                  block_hashes_cache_limit= 200 * 1000000,
                  db_type=None,
                  db=None,
                  app_proc_title="Connector")
                  
