#!/usr/bin/env bash

user=$1
commonkey=$4
round=0
sleeptime=0.03
pwrd="alicealice"

while true
do

  currentround=$(hcli query herb current-round)

  while !  hcli tx herb ct-part $commonkey -y --from $user> /dev/null
  do
    sleep $sleeptime

    if [ $(hcli query herb stage) = "stageDSCollecting" ]
    then
      break
    fi
  done

  stage=$(hcli query herb stage)

  while [ "$stage" != "stageDSCollecting" ]
  do
    sleep $sleeptime
    stage=$(hcli query herb stage)
  done

  while !  hcli tx herb decrypt $2 $3 -y --from $user> /dev/null
  do
    sleep $sleeptime

    if [ $(hcli query herb stage) = "stageCtCollecting" ] && [ $(hcli query herb current-round) -eq $(( $currentround + 1 )) ]
    then
      break
    fi

  done

  while [ $round -ne $(( $currentround + 1 )) ]
  do
    sleep $sleeptime
    round=$(hcli query herb current-round)
  done

done

