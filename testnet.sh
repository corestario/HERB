#!/usr/bin/env bash

if [[ $1 == "" ]]
then
      t=7
else
      t=$1
fi


if [[ $2 == "" ]]
then
      n=12
else
      n=$2
fi

echo "params: $t $n"

cur_path=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )

cd $cur_path
rm -rf ./vendor

rm -rf ./node0_config
mkdir ./node0_config

gopath=$(whereis go | grep -oP '(?<=go: ")(.*)(?= .*)' -m 1)
PATH=$gopath:$gopath/bin:$PATH

echo $GOBIN

make prepare
GO111MODULE=off


docker build -t herb_testnet .

HERBPATH=/go/src/github.com/dgamingfoundation/HERB

echo "run node0"

node0_full_id=$(docker run -d herb_testnet /bin/bash -c "$HERBPATH/scripts/init_chain.sh $t $n;
 sed -i 's/timeout_commit = "5s"/timeout_commit = "1s"/' /root/.hd/config/config.toml;
 hd start")
node0_id=${node0_full_id:0:12}

echo "run in background"
echo $node0_id

while  ! docker exec $node0_id /bin/bash -c "[[ -d /root/.hd ]]" ; do
sleep 1
echo "waiting ..."
done

docker cp $node0_id:/root/.hd ./node0_config/.hd
docker cp $node0_id:/root/.hcli ./node0_config/.hcli
docker cp $node0_id:$HERBPATH/bots ./node0_config/bots

node0_ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $node0_id)

node0_addr=$(cat ./node0_config/.hd/config/genesis.json | jq '.app_state.genutil.gentxs[0].value.memo')

echo node0_ip
echo $node0_ip

sed -i 's/seeds = ""/seeds = $node0_addr/' ./node0_config/.hd/config/config.toml

