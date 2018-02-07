#!/bin/bash

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

if [ -z "$DISPLAY" ]; then
	echo "\$DISPLAY must be set"
	exit
fi

echo "========================="
echo "= Reconfiguring SUMO... ="
echo "========================="
pushd $THIS_DIR/plexe-sumo/sumo
# build sumo
make -f Makefile.cvs
CPPFLAGS="-I/$THIS_DIR/include" ./configure
popd

# set up PATH so we can find OMNeT++
export PATH=$PATH:$THIS_DIR/omnetpp-5.0/bin


echo "=========================="
echo "= Reconfiguring Veins... ="
echo "=========================="
pushd $THIS_DIR/plexe-veins
CPPFLAGS="-I/$THIS_DIR/include" ./configure
popd
