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
          ------------------------          ----------------------------      |       =================
         |                        |        |   Zerro mq handlers        | ----|      | New transaction |
         |   Is blockchain        |  Yes   |   wait and process         | ---------> |  app handler    |
         |       synchronized?    | -----> |   new transactions and     |     |       =================
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
     | Preload  |      |  Blocks batch |                                              ==================
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

  The main starting parameters are _**last_block_height**_ and _**chain_tail**_.
  - _**last_block_height**_ this is the last blockchain block on which the application has stopped.
  - _**chain_tail**_ this is a chain of hashes of the last blockchain blocks.
  
  _**chain_tail**_ it is recommended to maintain 100 blocks for the Bitcoin mainnet, which corresponds to coinbase maturity.
  In other words, this is the number of hashes that guarantee that after this chain blockchain can no longer be changed.
  _**chain_tail**_ used to determine the main chain when reorganizing blocks in the blockchain.
  

An application built on top of this module should implement event handlers for the following events:
  
  - **new transaction** (_**tx_handler**_) called by the connector during normal operation after reaching the synchronization 
  position of the processed application block relative to the blockchain blocks
  
  - **before new block handler** (_**before_block_handler**_)  called by the connector during normal operation, when received new
  block but block not yet processed by connector and application. This is mean that not all block transactions may already
  received and handled, in case handler raise exception connector reject block and will try add this block again
  
  - **new block handler** (_**block_handler**_)  called by the connector during normal operation, when received new
  block and all block transactions already received and handled, in case handler raise exception connector 
  reject block and will try add this block again all blockchain state changes will be reverted
  
  - **after new block handler** (_**after_block_handler**_)  called by the connector during normal operation, 
  when received new block and block already processed, in case handler raise exception connector ignore it 
  all blockchain state changes already commited 
  
  
  - **remove last block** (_**orphan_handler**_) called during blockchain reorganization when last block no longer exist
  in main chain, in case handler raise exception all blockchain state changes will be reverted, connector  will 
  try remove this block again
  
  
  - **new block as transaction batch**  (_**block_batch_handler**_) called during blockchain synchronization process all
  block transaction provided as batch, in case handler raise exception connector will try add this block again 
  all blockchain state changes will be reverted
  
  - **flush application caches** (**_flush_app_caches_handler_**) called once synchronization completed and application
  implement synchronization cache in case handler raise exception connector stop working
  
  - **synchronization completed handler** (_**synchronization_completed_handler**_) called once synchronization completed 
  and all caches is flushed, it may be used for apply indexes to tables and other post sync staff tasks.
  
  
  In the connector there are 2 modes of operation. **Simple mode** - connector just provide transaction data to handlers.
  **UTXO mode** - connector handle utxo and each transaction inputs provided to handlers contains information about 
  address(script), coin amount and coin position in blockchain in case spending confirmed output. This mode required save
  information about UTXO in database. Connector able to work with 3 database engines: postgresql, leveldb, rocksdb.
  
  
## Synchronization

Synchronization time for bitcoin mainnet depends on perfomance of connector handlers and server hardware. Connector without
any handlers payload with bitcoind daemon installed on same server (CPU cores >= 8, SSD drives, RAM >=30 GB) 
synchronizes within 9 hours. Our application with transaction address map + history and transaction table with merkle proofs
  synchronizes within 10 hours + about 1 hour to create table indexes. 
  
    Blocks 576694; tx/s rate: 11678.21; io/s rate 59808.43; Uptime 9:52:6 
  

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
                  

## UTXO database schema

##### Postgresql

    connector_utxo (outpoint BYTEA,
                    pointer BIGINT,
                    address BYTEA,
                    amount  BIGINT,
                    PRIMARY KEY(outpoint))

**outpoint**  - byte string **[transaction hash | 32 bytes][output number | big endian]**

**pointer**  - integer  **[block_height | 25 bit][tx_index | 19 bit][tx_type = 0/1 | 1 bit][out_number | 19 bit]**

    >> outpoint = (block_height << 39)+(tx_index << 20)+(1 << 19) + out_number
    
**connector_utxo** this table contain all unspent outputs to get fast access for outputs related to address
crate this index after synchronisation is completed

    # simple index by address
    CREATE INDEX IF NOT EXISTS utxo_address_map ON connector_utxo USING BTREE (address);
    
    # index map by address and amount
    CREATE INDEX IF NOT EXISTS utxo_address_map_amount ON connector_utxo USING BTREE (address, amount);
    
    # index map by address and blockchain position (confirmation coint)
    CREATE INDEX IF NOT EXISTS utxo_address_map_pointer ON connector_utxo USING BTREE (address, pointer);


**address** - byte string **[out_type | 1 byte][addess hash/script]**

                    
    connector_unconfirmed_utxo (outpoint BYTEA,
                                out_tx_id BYTEA,
                                address BYTEA,
                                amount  BIGINT,
                                PRIMARY KEY(outpoint))

                                
    connector_unconfirmed_stxo (outpoint BYTEA,
                                sequence  INT,
                                out_tx_id BYTEA,
                                tx_id BYTEA,
                                input_index INT,
                                PRIMARY KEY(outpoint, sequence))
                                

**_connector_unconfirmed_stxo_** this table contains unconfirmed spent transaction outputs.
**outpoint** + **sequence** pair is unique identificator for table records, where the sequence is
the number of times a coin has been spent.



    connector_block_state_checkpoint (height  INT,
                                      data BYTEA,
                                      PRIMARY KEY height);  
                                  
**connector_block_state_checkpoint** this table contains information to restore blockchain state in case block removed