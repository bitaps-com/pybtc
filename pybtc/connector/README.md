Connector is a module for interacting with bitcoin node. This module is
expandable base for building bitcoin applications.

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