#!/bin/sh
echo
echo 'Current adresses:'
ip a sh | grep -e 'inet '| grep -v 'host lo' | grep -v 'docker'
echo
