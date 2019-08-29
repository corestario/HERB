#!/bin/bash
t1=$1
t2=$2
n=$3
rm -rf ~/.dkgcli
dkgcli gen-key-file $t2 $n
cd $HOME/.dkgcli
ck=$(cat keys.json | jq .common_key)
Ck=${ck:1:${#ck}-2}
rm -rf ~/.hcli
rm -rf ~/.hd
rm -rf ~/HERB/bots
mkdir ~/HERB/bots
hd init moniker --chain-id HERBchain
for (( i=0; i<$n; i++ ))
do
cd $HOME/.dkgcli
hcli keys add "client$i"
hd add-genesis-account $(hcli keys show "client$i" -a) 1000herbtoken,100000000stake
id=$(cat keys.json | jq .partial_keys[$i].id)
ID=${id:1:${#id}-2}
vk=$(cat keys.json | jq .partial_keys[$i].verification_key)
Vk=${vk:1:${#vk}-2}
hd add-key-holder $(hcli keys show "client$i" -a) $ID $Vk
pk=$(cat keys.json | jq .partial_keys[$i].private_key)
Pk=${pk:1:${#pk}-2}
cd $HOME/HERB/bots
echo "#!/usr/bin/expect -f
set timeout -1
cd $HOME/HERB/scripts 
spawn ./HERB client$i $Pk $ID $Ck
match_max 100000
while { true } {
expect \"Password to sign with 'client$i':\"
send -- \"alicealice\r\"
}
expect eof" > "client$i".exp
chmod +x ./"client$i".exp
done
hd set-threshold $t1 $t2
hd set-common-key $Ck
hcli config chain-id HERBchain
hcli config output json
hcli config indent true
hcli config trust-node true
hd gentx --name client0
hd collect-gentxs
hd validate-genesis
