#!/bin/bash

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

echo "======================="
echo "= Building Enclave... ="
echo "======================="
# compile enclave code
pushd $THIS_DIR/enclave/lib
make
popd

echo "===================="
echo "= Building SUMO... ="
echo "===================="
# build sumo
pushd $THIS_DIR/plexe-sumo/sumo
make -j$(nproc)
popd

# set up PATH so we can find OMNeT++
export PATH=$PATH:$THIS_DIR/omnetpp-5.0/bin


echo "====================="
echo "= Building Veins... ="
echo "====================="
# build veins
pushd $THIS_DIR/plexe-veins
make -j$(nproc)
popd
