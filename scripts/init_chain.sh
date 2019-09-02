#!/usr/bin/env bash

bots_path=$herb_path/bots

rm -rf $HOME/.hcli
rm -rf $HOME/.hd
rm -rf $bots_path

mkdir $bots_path

hd init moniker --chain-id HERBchain

hcli config chain-id HERBchain
hcli config output json
hcli config indent true
hcli config trust-node true

mkdir -p $HOME/.hd/config

cp $HOME/tmp/genesis.json $HOME/.hd/config
cp $HOME/tmp/config.toml $HOME/.hd/config
cp -r $HOME/tmp/keys $HOME/.hcli/
cp -r $HOME/tmp/bots $HOME/HERB/
sed -i 's/moniker = "moniker"/moniker = "node-'"$1"'"/' $HOME/.hd/config/config.toml
