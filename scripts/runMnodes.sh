#!/usr/bin/env bash

k=$1
m=$(($2-1))

cd /root/HERB/bots

for (( i=0; i<$m; i++ ))
do
  j=$(($k+$i))
  cd /root/HERB/bots
  ./"node$j".exp &
done

j=$(($k+$m))

./"node$j".exp
