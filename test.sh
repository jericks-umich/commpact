#!/bin/bash

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

source $THIS_DIR/setenv -f
pushd $THIS_DIR/plexe-veins/examples/platooning/
./run "$@"
popd
