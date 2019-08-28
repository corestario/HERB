#!/usr/bin/env bash

dir_path=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )
herb_path=$dir_path/..
bots_path=$herb_path/bots

rm -rf /root/.hcli
rm -rf /root/.hd
rm -rf /root/HERB/bots

mkdir /root/HERB/bots

hd init moniker --chain-id HERBchain

hcli config chain-id HERBchain
hcli config output json
hcli config indent true
hcli config trust-node true

mkdir -p /root/.hd/config

cp /root/tmp/genesis.json /root/.hd/config
cp /root/tmp/config.toml /root/.hd/config
cp -r /root/tmp/keys /root/.hcli/
cp -r /root/tmp/bots /root/HERB/

sed -i 's/moniker = "moniker"/moniker = "node-'"$1"'"/' /root/.hd/config/config.toml
