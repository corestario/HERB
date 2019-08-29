#!/bin/bash
ssh -o StrictHostKeyChecking=no root@$4 << HERE
	./HERB/scripts/startchain $1
	hd start &
	./HERB/scripts/runMnodes $2 $3
HERE
