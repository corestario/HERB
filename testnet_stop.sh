#!/usr/bin/env bash

nodeArray=$(cat nodeArray.txt)

docker stop ${nodeArray[@]}
docker rm ${nodeArray[@]}