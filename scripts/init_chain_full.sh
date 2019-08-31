#!/usr/bin/env bash

t1=$1
t2=$2
n=$3

dir_path=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )
bots_path=$HOME/HERB/bots

rm -rf $HOME/.dkgcli

pwrd="alicealice"

dkgcli gen-key-file $t2 $n

cd $HOME/.dkgcli

ck=$(cat keys.json | jq .common_key)
Ck=${ck:1:${#ck}-2}

rm -rf $HOME/.hcli
rm -rf $HOME/.hd
rm -rf $bots_path

mkdir $bots_path

hd init moniker --chain-id HERBchain

for (( i=0; i<$n; i++ ))
do
    cd $HOME/.dkgcli

    hcli keys add "client$i" <<< $pwrd

    hd add-genesis-account $(hcli keys show "client$i" -a) 1000herbtoken,100000000stake

    id=$(cat keys.json | jq .partial_keys[$i].id)
    ID=${id:1:${#id}-2}

    vk=$(cat keys.json | jq .partial_keys[$i].verification_key)
    Vk=${vk:1:${#vk}-2}

    hd add-key-holder $(hcli keys show "client$i" -a) $ID $Vk

    pk=$(cat keys.json | jq .partial_keys[$i].private_key)
    Pk=${pk:1:${#pk}-2}

    cd $bots_path

    scripts_path='$HOME/HERB/scripts'
    echo "#!/usr/bin/expect -f
        set timeout -1
        cd $dir_path
 
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

hd gentx --name client0 <<< $pwrd
hd collect-gentxs
hd validate-genesis
