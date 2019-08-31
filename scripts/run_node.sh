#!/usr/bin/env bash

ssh -o StrictHostKeyChecking=no root@$4 << HERE
    ./HERB/scripts/init_chain.sh $1
    hd start &
    ./HERB/scripts/run_clients.sh $2 $3
HERE
