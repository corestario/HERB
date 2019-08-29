# HERB
Homomorphic Encryption Random Beacon

### What is it

This repo contains cosmos-application which allows to generate random numbers in a secure way. It's based on the HERB-protocol.

Simplified protocol description:

1. New round *i* is starting. 
2. Each participant sends *ciphertext part* (protocol message type) to the blockchain (as transaction). 
3. After receiving *t1* ciphertext parts, the common ciphertext is being aggregated. 
4. Each participant sends *decryption share* (again, message type) to the blockchain (as transaction).
5. After receiving *t2* decryption shares, round is completed. New round is *i+1*, go to step 1. 

### How it works

There are two types of entities who maintains the system: 

* Blockchain full nodes who run application daemon (hd). Let's denote them as *nodes*. 

* Scripts ([HERB](scripts/HERB)) which represents protocol participants. Let's call them *clients*. 

  Clients use application command line interface for querying app state and sending transactions.  

### How to run it locally

1. [Install Go](https://golang.org/doc/install)

2. Install dependencies: 

   ```bash
   sudo apt-get install expect -y
   sudo apt-get install make -y
   sudo apt-get install jq -y
   ```

   

3. Clone [repository](https://github.com/dgamingfoundation/HERB/tree/master) to the $HOME directory

4. Install application:

   ```bash
   cd ~/HERB
   make install
   ```

5. Run setup script:

   ```
   ./scripts/init_chain.exp 2 3
   ```

   Here *t1* = *t2* = 2, *n* = 3. *n* is a  total number of clients, *t1, t2* is a thresholds (see simplified protocol description). `init_chain.exp` initializes blockchain parameters and creates clients' secret keys (bots folder). 

6. Run application daemon:

   ```
   hd start
   ```

   Now node is running and blocks are being generated. 

7. In another terminal run clients:

   ```
   ./scripts/runMnodes 0 3
   ```

   *runMnodes k j* runs *j* clients (bot$i.exp files) starting from k-th client. For instance, command above runs 3 client: bot0.exp, bot1.exp, bot2.exp. 

8. Random number generation process is started! You can check the current HERB round by query:

   ```
   hcli query herb current-round
   ```

9. You can get the random number generated at the round $j by query:

   ```
   hcli query herb get-random $j
   ```

   

### How to run a distributed testnet

For Ubuntu:

1. Create two DigitalOcean ubuntu-droplets (we'll call them node-00 and node-01). 

   First one is a "zero"-node, which run full setup phase. Second one is a "blueprint" which will be duplicated later. 

3. Send DigitalOcean associated ssh-keys to node-00:

   ```
   scp -r %ssh-keys path% root@%node-00 ip%:.ssh/
   ```

4. Connect to node-00 and perform  actions below:

   1. Run machine_setup.sh script. It installs Go and other required software.

   2. Clone [repository](https://github.com/dgamingfoundation/HERB/tree/master) to the $HOME directory.

   3. Install application:

      ```bash
      cd ~/HERB
      make install
      ```

   4. Run setup script:

      ```
      ./scripts/init_chain.exp 2 2 3
      ```

      Here *t1* = *t2* = 2, *n* = 3. *n* is a  total number of clients, *t1, t2* is a thresholds (see simplified protocol description). `init_chain.exp` initializes blockchain parameters and creates clients' secret keys (bots folder). 

   5. Send configuration files and keys to node-01:

      ```
      scp .hd/config/genesis.json root@%node-01 ip%:
      
      scp -r .hcli/keys root@%node-01 ip%:
      
      scp .hd/config/config.toml root@%node-01 ip%:
      
      scp -r HERB/bots root@%node-01 ip%:
      ```

   6. Run app daemon:

      ```
      hd start
      ```

5. Connect to node-00 again:

   1. Get node-00 tendermint-id:

      ```
      hcli status
      ```

      and save "id" value somewhere. 

   2. Run Prometheus:

      ```
      cd prometheus-2.11.1.linux-amd64
      ./prometheus --config.file=$HOME/HERB/prometheus.yml
      ```

6. Connect to node-01:

   1. Run `machine_setup.sh` script.

   2. Clone [repository](https://github.com/dgamingfoundation/HERB/tree/master) to the $HOME directory

   3. Install application:

      ```bash
      cd ~/HERB
      make install
      ```

7. Now node-01 is our blueprint for other nodes. Make a DigitalOcean snapshot of the node-01.

8. Create as mush droplets from node-01 snapshot as you need.

9. Copy IPs all nodes except node-00 to `HERB/scripts/servers.txt` on your own machine.

10. Launch all application daemons and clients on the nodes from server.txt file:

    ```
    .$HOME/HERB/scripts/run_testnet.sh $HOME/HERB/scripts/servers.txt %first node number% %client per node%
    ```

    Here is two arguments:

    * first node number - define moniker for node daemon and the number of the first launching client
    * client per node - define how many clients (bots files) will be launched on the each node

    For example: if we run the command with three IPs in the server.txt  file:

    ```
    .$HOME/HERB/scripts/run_testnet.sh $HOME/HERB/scripts/servers.txt 0 3
    ```

    It will launch clients: `bot0.exp`, `bot1.exp`, `bot2.exp` on the first node; `bot3.exp`, `bot4.exp`, `bot5.exp` on the second node; `bot6.exp`, `bot7.exp`, `bot8.exp`  on the third node.

