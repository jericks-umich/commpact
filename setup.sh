#!/bin/bash

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# must download version 5.0 (not latest version) of OMNeT++ and place in this
# directory before beginning

echo "Installing OMNeT++ and SUMO dependencies..."
# dependencies listed here in comments
# For OMNeT++
sudo apt-get install -y build-essential gcc g++ bison flex perl qt5-default \
	tcl-dev tk-dev libxml2-dev zlib1g-dev default-jre doxygen graphviz \
	libwebkitgtk-3.0-0 
#TODO add the rest
# For SUMO


echo "Creating necessary symlinks for building..."
# symlink the .h files we need into the include directory
mkdir -p $THIS_DIR/include
ln -s $THIS_DIR/enclave/lib/App/commpact.h $THIS_DIR/include/

# symlink the .so files we need into the lib directory
mkdir -p $THIS_DIR/lib
ln -s $THIS_DIR/enclave/lib/libcommpact.so.1 $THIS_DIR/lib

# symlink the enclave .so to /tmp
ln -s $THIS_DIR/enclave/lib/enclave.signed.so /tmp/

echo "Downloading OMNet++..."
# download OMNeT++
pushd $THIS_DIR
wget -nv --user-agent='Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0' --header='Referer: https://www.omnetpp.org/component/jdownloads/category/32-release-older-versions?start=10' https://www.omnetpp.org/component/jdownloads/send/32-release-older-versions/2305-omnetpp-50-linux -O omnetpp-5.0.tgz
echo "Unpacking OMNet++"
tar -xf omnetpp-5.0.tgz
rm omnetpp-5.0.tgz
echo "Building OMNet++"
cd omnetpp-5.0/
source ./setenv
./configure
make -j$(nproc)
popd

# set up PATH so we can find OMNeT++
#export PATH=$PATH:$THIS_DIR/omnetpp-5.0/bin

# set sumo up for building
pushd $THIS_DIR/plexe-sumo/sumo
git pull
git checkout plexe-2.0
make -f Makefile.cvs
export CPPFLAGS="-I/$THIS_DIR/include"
./configure
make -j$(nproc)
popd
