#!/usr/bin/env bash

i=$(($2))
j=$((0))

while IFS= read -r line; do
    s=$(($i*$3 + $j))

    gnome-terminal -x ./run_node.sh $i $s $3 $line

    j=$(($j+1))

    if [[ $j==$3 ]]; then
        j=$((0))
    fi

    i=$(($i+1))
done < "$1"
