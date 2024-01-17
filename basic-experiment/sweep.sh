#!/bin/bash
set -m

offset=0
sleep_time=3

while [ "$offset" -lt "4096" ]
do
  offset_hex=$( printf "%x" $offset )
  echo "Offset: 0x${offset_hex}"

  LD_LIBRARY_PATH=../sgx-step/sdk/intel-sdk/linux-sgx/psw/urts/linux/ ./basic_experiment "be_offset_0x${offset_hex}.log" "0x${offset_hex}" > std_offset_0x${offset_hex}.out & export p=$! && fg 

  offset=$((offset + 4))

  next_sleep_time=${sleep_time}
  echo "Sleep $next_sleep_time"
  sleep $next_sleep_time
  
  pkill -P $p
  kill -9 $(ps -aux | grep 4k | tr -s " " | cut -d " " -f 2)
done
