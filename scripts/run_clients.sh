#!/bin/bash

k=$1
m=$(($2-1))
for (( i=0; i<$m; i++ ))
do
j=$(($k+$i))
cd $HOME/HERB/bots
./"node$j".exp &
done
j=$(($k+$m))
./"node$j".exp
