#!/bin/bash

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# must download version 5.0 (not latest version) of OMNeT++ and place in this
# directory before beginning

# dependencies listed here in comments
# TODO


export PATH=$PATH:$THIS_DIR/omnetpp-5.0/bin
export PATH=$PATH:$THIS_DIR/plexe-sumo/sumo/bin

# symlink the .h files we need into the include directory
mkdir -p $THIS_DIR/include
ln -s $THIS_DIR/enclave/lib/App/commpact.h $THIS_DIR/include/

# symlink the .so files we need into the lib directory
mkdir -p $THIS_DIR/lib
ln -s $THIS_DIR/enclave/lib/libcommpact.so.1 $THIS_DIR/lib

# symlink the enclave .so to /tmp
ln -s $THIS_DIR/enclave/lib/enclave.signed.so /tmp/
