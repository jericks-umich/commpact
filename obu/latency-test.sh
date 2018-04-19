#!/bin/bash
#
# $1: total number of packets for each experiment
# $2: some description text for current experiments
# optional:
#   $3: channel number [Default: 178] (172, 174, 175, 176, 178, 180, 181, 182, 184)
#   $4: data rate [Default: 12] (6, 9, 12, 18, 24, 27, 36, 48, 54)
#   $5: transmission power [Default: 32] ([-64, 64])
#

echo "========================"
echo "DSRC Latency Measurement"
echo "========================"

# parameters
channelNumber=178
dataRate=12
txPower=32

if [ $# -gt 2 ]; then
    channelNumber=$3
fi
if [ $# -gt 3 ]; then
    dataRate=$4
fi
if [ $# -gt 4 ]; then
    txPower=$5
fi
echo "Rounds: $1"
echo "Description: $2"
echo "Channel: $channelNumber"
echo "Data Rate: $dataRate"
echo "Tx Power: $txPower"

# check results directories
logDir="results_"$channelNumber"_"$dataRate"_"$txPower
if [ ! -d $logDir ]; then
    mkdir $logDir
fi
echo "Log Dir: $logDir"
echo "============"

n=8
size=128
for i in `seq 1 $n`; do
    size=$((128 + ($i - 1) * 64))
    echo "Packet Size: $size"

    logFile=$logDir"/"$1"_"$2"_"$size".log"
    echo "Log: $logFile"

    for j in `seq 1 $1`; do
        ./client $size $channelNumber $dataRate $txPower | tee -a $logFile
    done

    echo "Done!"
    echo "============"
done
