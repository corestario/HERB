#!/usr/bin/env bash

while test $# -gt 0; do
  case "$1" in
    -h|--help)
      echo "testnet - run HERB testnet"
      echo " "
      echo "testnet [options]"
      echo " "
      echo "options:"
      echo "-h, --help                show brief help"
      echo "-t, --treshhold=t         specify a treshhold"
      echo "-n, --maximum_nodes=n     specify maximum node count"
      echo "-c, --node_count=n        specify node count"
      exit 0
      ;;
    -t|--treshhold)
      shift
      if test $# -gt 0; then
        export t=$1
      else
        echo "no treshhold specified"
        exit 1
      fi
      shift
      ;;
    -n|--maximum_nodes)
      shift
      if test $# -gt 0; then
        export n=$1
      else
        echo "no maximum_nodes specified"
        exit 1
      fi
      shift
      ;;
    -c|--node_count)
      shift
      if test $# -gt 0; then
        export node_count=$1
      else
        echo "no node_count specified"
        exit 1
      fi
      shift
      ;;
    --no_rebuild)
      NOREBUILD=true
      shift
      ;;
    *)
      break
      ;;
  esac
done


if [[ t == "" ]]
then
      t=7
fi


if [[ n == "" ]]
then
      n=12
fi

node_count=$((n+1))
echo $node_count

echo "params: $t $n"
echo "node_count: $node_count"

cur_path=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )

cd $cur_path
rm -rf ./vendor

rm -rf ./node0_config
mkdir ./node0_config

gopath=$(whereis go | grep -oP '(?<=go: ")(.*)(?= .*)' -m 1)
PATH=$gopath:$gopath/bin:$PATH

echo $GOBIN

if [[ $NOREBUILD ]]
then
  echo "no rebuild"
else
  make prepare
  GO111MODULE=off

  docker build -t herb_testnet .
fi

HERBPATH=/go/src/github.com/dgamingfoundation/HERB

echo "run node0"

node0_full_id=$(docker run -d herb_testnet /bin/bash -c "$HERBPATH/scripts/init_chain.sh $t $node_count;
 sed -i 's/timeout_commit = "5s"/timeout_commit = "1s"/' /root/.hd/config/config.toml;
 hd start")
node0_id=${node0_full_id:0:12}

echo "node0: $node0_id"
echo

while  ! docker exec $node0_id /bin/bash -c "[[ -d /root/.hd ]]" ; do
sleep 2
echo "waiting ..."
done

sleep 10

docker cp $node0_id:/root/.hd ./node0_config/.hd
docker cp $node0_id:/root/.hcli ./node0_config/.hcli
docker cp $node0_id:$HERBPATH/bots ./node0_config/bots

chmod -R 0777 ./node0_config

node0_addr=$(cat ./node0_config/.hd/config/genesis.json | jq '.app_state.genutil.gentxs[0].value.memo')

echo node0_addr
echo $node0_addr

if [[ -z $node0_addr ]] || [[ $node0_addr == "null" ]] || [[ $node0_addr == null ]]
then
  echo "ERROR"
  exit 1
fi

sed -i "s/seeds = \"\"/seeds = $node0_addr/" ./node0_config/.hd/config/config.toml

nodeArray=($node0_id)

node_count=$((node_count-1))

for ((i=1;i<=$node_count;i++));
do
    nodeN_full_id=$(docker create -t herb_testnet /bin/bash -c "$HERBPATH/scripts/startchain.sh $i && hd start")
    nodeN_id=${nodeN_full_id:0:12}

    nodeArray+=($nodeN_id)

    docker cp ./node0_config/.hd/config/config.toml $nodeN_id:/root/tmp/
    docker cp ./node0_config/.hd/config/genesis.json $nodeN_id:/root/tmp/
    docker cp ./node0_config/.hcli/keys $nodeN_id:/root/tmp/
    docker cp ./node0_config/bots $nodeN_id:/root/tmp/

    docker start $nodeN_id

    echo "node_num: $i, node_id: $nodeN_id"

done

sleep 5

echo "${nodeArray[@]}" > nodeArray.txt
chmod 0777 ./nodeArray.txt

echo "${nodeArray[@]}"
echo "all nodes started"
echo "run runMnodes"

for ((i=0;i<=$node_count;i++));
do
  nodeN_id=${nodeArray[$i]}
  docker exec -t -d $nodeN_id /bin/bash -c "$HERBPATH/scripts/runMnodes.sh $i 1"

  echo "node_num: $i, node_id: $nodeN_id"
done