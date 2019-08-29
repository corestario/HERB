#!/bin/bash

k=$1
m=$(($2-1))
cd $HOME/HERB/bots
for (( i=0; i<$m; i++ ))
do
j=$(($k+$i))
./"client$j".exp &
done
j=$(($k+$m))
./"client$j".exp
