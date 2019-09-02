#!/usr/bin/env bash

sudo apt-get update -y
sudo apt-get upgrade -y

sudo apt-get install expect -y
sudo apt-get install make -y
sudo apt-get install jq -y

wget https://dl.google.com/go/go1.12.6.linux-amd64.tar.gz
sudo tar -xvf go1.12.6.linux-amd64.tar.gz
sudo mv go /usr/local

mkdir $HOME/go-path
sed -i '$a export GOPATH=$HOME/go-path' .profile
sed -i '$a export GOROOT=/usr/local/go' .profile
sed -i '$a export PATH=$GOPATH/bin:$GOROOT/bin:$PATH' .profile
source ~/.profile

wget https://github.com/prometheus/prometheus/releases/download/v2.11.1/prometheus-2.11.1.linux-amd64.tar.gz
sudo tar -xvf prometheus-2.11.1.linux-amd64.tar.gz
