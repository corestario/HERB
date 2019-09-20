# HERB - Homomorphic Encryption Random Beacon
HERB is a Publicly Verifiable Random Beacon protocol described in [this]() article. This repository is HERB implementation written in [Golang](https://golang.org) as [Cosmos](https://github.com/cosmos/cosmos-sdk) application using [Kyber](https://github.com/dedis/kyber) library.

### What is it

This repo contains cosmos-application which allows securely generating random numbers. It's based on the HERB-protocol.

Simplified protocol description:

1. New round *i* is starting. 
2. Each participant sends *ciphertext part* (protocol message type) to the blockchain (as transaction). 
3. After receiving *t1* ciphertext parts, the common ciphertext is being aggregated. 
4. Each participant sends *decryption share* (again, message type) to the blockchain (as transaction).
5. After receiving *t2* decryption shares, round is completed. New round is *i+1*, go to step 1. 

###  Table of Contents

* [Disclaimer](#disclaimer)
* [Implementation details](#implementation-details)
* [Blockchain and Clients](#blockchain-and-clients)
* [How to run it locally](#how-to-run-it-locally)
* [How to run a local testnet with Docker](#how-to-run-a-local-testnet-with-docker)
* [How to run a distributed testnet with Digital Ocean](#how-to-run-a-distributed-testnet-with-digital-ocean)

### Disclaimer

**This software is considered experimental. DO NOT USE it for anything security critical at this point.**



### Implementation details

This is a Proof-of-Concept implementation, so some details from original paper are simplified here. 

Recall, that there are 3 protocol phase (page 12):

* Setup phase. Main purpose of the setup phase is keys generating.  DKG phase (Section 3.1, page 13) is skipped in this implementation. `dkgcli` simulates DKG-phase and generates private/public keys. These keys are saved in the `bots` folder. 
* Publication phase. Each entropy provider sends ciphertext part and proofs using `hcli tx herb ct-part` command.
* Disclosure phase. Each key holder sends decryptions share and proofs using `hcli tx herb decrypt` command. 

Entropy Providers and Key Holders (page 12) are the same set. 



Let's look at the original HERB protocol (page 17) closer and compare it with this implementation. .

> 1. Each entropy provider *e<sub>j</sub>*, *1 ≤ j ≤ m*, generates random point *M<sub>j</sub> ∈ __G__*. Then encrypts it:
> 2. e<sub>j</sub> publishes *C<sub>j</sub>* along with NIZK of discrete logarithm knowledge for *A<sub>j</sub>* and NIZK of representation knowledge for *B<sub>j</sub>* 

`hcli tx herb ct-part [commonPubKey]` [command](https://github.com/dgamingfoundation/HERB/blob/master/x/herb/client/cli/tx.go#L42) calculates ciphertext part and RK/DLK proofs and sends transaction with a [Ciphertext Part Message](https://github.com/dgamingfoundation/HERB/blob/master/x/herb/types/msgs.go#L13). 

> 3.  When *C<sub>j</sub>* is published, participants agree that the ciphertext part is correct, if both conditions __DLK-Verify__*(π<sub>DLK<sub>j</sub></sub>, A<sub>j</sub>, G) = 1* and __RK-Verify__*(π<sub>RK<sub>j</sub></sub>, G, Q, B<sub>j</sub>) = 1* met.
> 4.  When all correct *C<sub>j</sub>* are published, participants calculate *C = (A, B)*

On the blockchain side, [keeper's function](https://github.com/dgamingfoundation/HERB/blob/master/x/herb/keeper.go#L44) validates the ciphertext part and store it into the blockchain. This function also aggregate the ciphertext with cyphertexts which are already stored. 

Anyone can see stored ciphertexts by query: 

`hcli query herb all-ct [round]`

As soon as *t1* ciphertext parts were stored, application stage changes to "decryption phase" for current round.

> 5.  Key holder *id<sub>i</sub>*, *1 ≤ i ≤ n*, publishes decryption shares along with NIZK of discrete logarithm equality

`hcli tx herb decrypt decrypt [privateKey] [ID]` [command](https://github.com/dgamingfoundation/HERB/blob/master/x/herb/client/cli/tx.go#L81) queries an aggregated ciphertext and calculates a decryption share. This command also sends transaction with [Decryption Share message](https://github.com/dgamingfoundation/HERB/blob/master/x/herb/types/msgs.go#L68).

Anyone can query aggregated ciphertext by command:

`hcli query herb aggregated-ct [round]`

> 6. When *D<sub>i</sub>* is published, participants verify that __DLE-Verify__*(π<sub>DLE<sub>i</sub></sub>,D<sub>i</sub>,A,VK<sub>i</sub>,G) = 1*

On the blockchain side, [keeper's function](https://github.com/dgamingfoundation/HERB/blob/master/x/herb/keeper.go#L148) validates the decryption share and store it into the blockchain. 

Anyone can see stored decryption shares by query: 

`hcli query herb all-shares [round]`

> 7. When *t2* decryption shares published, participants calculate *M*

As soon as *t2* decryption shares were stored, application decrypts an aggregated ciphertext and changes current round stage to "completed". New round is being started. 

Anyone can see generated random number by query:

`hcli query herb get-random [round]`



HERB round changing depends on transactions by Entropy Providers and Key Holders and doesn't depend on underlying blockchain height. So one HERB round can take 1 block or 10 blocks, it depends only on HERB participants and blockchain throughput. Anyone can query current round by command:

`hcli query herb current-round`



### Blockchain and Clients.

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

10. You can get the random number generation results by query:

   ```
hcli query herb get-random %round-number%
   ```

  

### How to run a local testnet with Docker

1. Run the `testnet.sh` script:

   ```
   cd $HOME/HERB
   ./testnet.sh
   ```

   Script will display see created docker containers' id. 

   You can get help:

   ```
   ./testnet.sh -h
   ```

2. If you want to check the random numbers generation process, then connect to the docker container:

   ```
   sudo docker exec -it %container-id% /bin/bash 
   ```

3. Then you can use hcli commands:

   ```
   hcli query herb current-round
   hcli query herb get-random %round-number%
   ```

4. To stop the testnet run:

   ```
   ./testnet_stop.sh
   ```

   

### How to run a distributed testnet with Digital Ocean

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

4. Connect to node-00 and perform  actions below:

   1. Export environment variables:

      ```
      source ~/.profile
      ```

   2. Clone [repository](https://github.com/dgamingfoundation/HERB/tree/master) to the $HOME directory.

      ```
      git clone https://%username%@github.com/dgamingfoundation/HERB
      ```

   3. Install application:

      ```
      cd ~/HERB
      make install
      ```

   4. Run setup script:

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
      scp $HOME/.hd/config/genesis.json root@%node-01-ip%:
      
      scp -r $HOME/.hcli/keys root@%node-01-ip%:
      
      scp $HOME/.hd/config/config.toml root@%node-01-ip%:
      
      scp -r $HOME/HERB/bots root@%node-01-ip%:
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

   1. Export environment variables:

      ```
      source ~/.profile
      ```

   2. Clone [repository](https://github.com/dgamingfoundation/HERB/tree/master) to the $HOME directory

      ```
      git clone https://%username%@github.com/dgamingfoundation/HERB
      ```

   3. Install application:

      ```
      cd ~/HERB
      make install
      ```

   4. Set node-00 as seed for tendermint:

      ```
      sed -i 's/seeds = ""/seeds = "%node-00 id%@%node-00 ip%:26656"/' tmp/config.toml
      ```

8. Now, node-01 is our blueprint for other nodes. Make a DigitalOcean snapshot of the node-01.

9. Create as mush droplets from node-01 snapshot as you need.

10. Copy IPs all nodes except node-00 to `HERB/scripts/servers.txt` line by line on your machine.

11. Launch all application daemons and clients on the nodes from server.txt file:

    ```
    cd $HOME/HERB/scripts
    ./run_distributed_testnet.sh servers.txt %first node number% %client per node%
    ```

    Here are two arguments:

    * first node number - define moniker for node daemon and the number of the first launching client
    * client per node - define how many clients (bots files) will be launched on each node

    For example: if we run the command with two IPs in the server.txt  file:

    ```
    ./run_distributed_testnet.sh servers.txt 1 3
    ```

    It will launch clients: `client3.exp`, `client4.exp`, `client5.exp` on the second node; `client6.exp`, `client7.exp`, `client8.exp`  on the third node.

12. Now you can check the progress by querying current-round:

    ```
    hcli query herb current-round
    ```
