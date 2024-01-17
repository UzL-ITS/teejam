#!/bin/bash

sudo cpupower -c all frequency-set -g performance
# source linux-sgx-local-install/sgxsdk/environment
pushd sgx-step/kernel
make clean load
popd 
sudo modprobe msr
for i in 0 1 2 3 4 5 6 7; do sudo wrmsr -p $i 0x1A4 0xF; done
