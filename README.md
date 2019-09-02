# HERB
Homomorphic Encryption Random Beacon

### What is it

This repo contains cosmos-application which allows securely generating random numbers. It's based on the HERB-protocol.

Simplified protocol description:

1. New round *i* is starting. 
2. Each participant sends *ciphertext part* (protocol message type) to the blockchain (as transaction). 
3. After receiving *t1* ciphertext parts, the common ciphertext is being aggregated. 
4. Each participant sends *decryption share* (again, message type) to the blockchain (as transaction).
5. After receiving *t2* decryption shares, round is completed. New round is *i+1*, go to step 1. 

### How it works

There are two types of entities who maintain the system: 

* Blockchain full nodes who run application daemon (hd). Let's denote them as *nodes*. 

* Scripts ([HERB](scripts/HERB)) which represents protocol participants. Let's call them *clients*. 

  Clients use application command line interface for querying app state and sending transactions.

### How to run it locally

1. [Install Go](https://golang.org/doc/install)

2. Install dependencies: 

   ```
   sudo apt-get install expect -y
   sudo apt-get install make -y
   sudo apt-get install jq -y
   ```

   

3. Clone [repository](https://github.com/dgamingfoundation/HERB/tree/master) to the $HOME directory

4. Install application:

   ```
   cd ~/HERB
   make install
   ```

5. Run setup script:

   ```
   cd scripts
   ./init_chain_full.sh t1 t2 n
   ```

   For example, *t1* = *t2* = 2, *n* = 3. *n* is a  total number of clients, *t1, t2* is a thresholds (see simplified protocol description). `init_chain.exp` initializes blockchain parameters and creates clients' secret keys (bots folder). 

6. Setup blocktime:

   ```
   cd $HOME/.hd/config
   sed -i 's/timeout_commit = "5s"/timeout_commit = "1s"/' config.toml;
   ```

7. Run application daemon:

   ```
   hd start
   ```

   Now node is running and blocks are being generated. 

8. In another terminal run clients:

   ```
   cd $HOME/HERB
   ./scripts/run_clients.sh k j
   ```

   `run_clients k j` runs *j* clients (bot%i%.exp files) starting from *k*-th client. For instance, for *k*=0, *j*=3 it runs 3 client: client0.exp, client1.exp, client2.exp. 

9. Random number generation process is started! You can check the current HERB round by query:

   ```
   hcli query herb current-round
   ```

10. You can get the random number generated at the round $j by query:

   ```
   hcli query herb get-random $j
   ```

   

### How to run a distributed testnet

For Ubuntu:

1. Create two DigitalOcean ubuntu-droplets (we'll call them node-00 and node-01). 

   The first one is a "zero"-node, which runs full setup phase. The second one is a "blueprint" which will be duplicated later. 

3. Send DigitalOcean associated ssh-keys to node-00:

   ```
   scp %ssh-keys path% root@%node-00 ip%:.ssh/
   ```
4. Run machine_setup.sh script for both nodes. It installs Go and other required software.

   ```
   cd $HOME/HERB/scripts
   ssh root@%node-ip% 'bash -s' < machine_setup.sh
   ```

5. Connect to node-00 and perform  actions below:

   0. 
      ```
      source ~/.profile
      ```

   1. Clone [repository](https://github.com/dgamingfoundation/HERB/tree/master) to the $HOME directory.

      ```
      git clone https://%username%@github.com/dgamingfoundation/HERB
      ```

   2. Install application:

      ```
      cd ~/HERB
      make install
      ```

   3. Run setup script:

      ```
      cd $HOME/HERB/scripts
      ./init_chain_full.sh t1 t1 n
      ```

     For example, *t1* = *t2* = 2, *n* = 3. *n* is a  total number of clients, *t1, t2* is a thresholds (see simplified protocol description). `init_chain.exp` initializes blockchain parameters and creates clients' secret keys (bots folder).

   4. Setup blocktime:

      ```
      cd $HOME/.hd/config
      sed -i 's/timeout_commit = "5s"/timeout_commit = "1s"/' config.toml
      ``` 

   5. Send configuration files and keys to node-01:

      ```
      scp $HOME/.hd/config/genesis.json root@%node-01-ip%:tmp/
      
      scp -r $HOME/.hcli/keys root@%node-01-ip%:tmp/
      
      scp $HOME/.hd/config/config.toml root@%node-01-ip%:tmp/
      
      scp -r $HOME/HERB/bots root@%node-01-ip%:tmp/
      ```

   6. Run app daemon:

      ```
      hd start
      ```

6. Connect to node-00 again:

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
6. Connect to node-00 one more time:
   1. Run first clients:

      ```
      cd $HOME/HERB/scripts
      ./run_clients.sh 0 %k%
      ```
    
      `run_clients k j` runs *j* clients (bot%i%.exp files) starting from *k*-th client. Other clients will be launched by the `run_testnet.sh` script later.

7. Connect to node-01:

   0. 
      ```
      source ~/.profile
      ```

   1. Clone [repository](https://github.com/dgamingfoundation/HERB/tree/master) to the $HOME directory

      ```
      git clone https://%username%@github.com/dgamingfoundation/HERB
      ```

   2. Install application:

      ```
      cd ~/HERB
      make install
      ```

   3. Set node-00 as seed for tendermintL

      ```
      sed -i 's/seeds = ""/seeds = "%node-00 id%@%node-00 ip%:26656"/' tmp/config.toml
      ```

8. Now, node-01 is our blueprint for other nodes. Make a DigitalOcean snapshot of the node-01.

9. Create as mush droplets from node-01 snapshot as you need.

10. Copy IPs all nodes except node-00 to `HERB/scripts/servers.txt` line by line on your machine.

11. Launch all application daemons and clients on the nodes from server.txt file:

    ```
    cd $HOME/HERB/scripts
    ./run_testnet.sh servers.txt %first node number% %client per node%
    ```

    Here are two arguments:

    * first node number - define moniker for node daemon and the number of the first launching client
    * client per node - define how many clients (bots files) will be launched on each node

    For example: if we run the command with two IPs in the server.txt  file:

    ```
    ./run_testnet.sh servers.txt 1 3
    ```

    It will launch clients: `client3.exp`, `client4.exp`, `client5.exp` on the second node; `client6.exp`, `client7.exp`, `client8.exp`  on the third node.

12. Now you can check the progress by querying current-round:

    ```
    hcli query herb current-round
    ```
