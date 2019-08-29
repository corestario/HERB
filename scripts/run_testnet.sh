#!/bin/bash
i=$(($3))
j=$((0))
while IFS= read -r line; do
    s=$(($i*$2 + $j))
    ./run_node.sh $i $s $2 $line
    j=$(($j+1))
    if [[ $j==$2 ]]; then
        j=$((0))
    fi
    i=$(($i+1))
done < "$1"
