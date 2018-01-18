#!/bin/bash

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"


echo "==============================================="
echo "= Installing OMNeT++ and SUMO dependencies... ="
echo "==============================================="
# dependencies listed here in comments
# For OMNeT++
sudo apt-get install -y build-essential gcc g++ bison flex perl qt5-default \
	tcl-dev tk-dev libxml2-dev zlib1g-dev default-jre doxygen graphviz \
	libwebkitgtk-3.0-0 openjdk-6-jre autoconf libtool libproj-dev libgdal-dev \
	libfox-1.6-dev libxerces-c-dev r-base libqt4-dev 
#TODO add the rest
# For SUMO

echo "======================="
echo "= Building Enclave... ="
echo "======================="
# compile enclave code
pushd $THIS_DIR/enclave/lib
make
popd

echo "===================================================="
echo "= Creating necessary symlinks for building SUMO... ="
echo "===================================================="
# symlink the .h files we need into the include directory
mkdir -p $THIS_DIR/include
ln -s $THIS_DIR/enclave/lib/App/commpact.h $THIS_DIR/include/
ln -s $THIS_DIR/enclave/lib/include/commpact_status.h $THIS_DIR/include/

# symlink the .so files we need into the lib directory
mkdir -p $THIS_DIR/lib
ln -s $THIS_DIR/enclave/lib/libcommpact.so.1 $THIS_DIR/lib
ln -s $THIS_DIR/enclave/lib/libcommpact.so.1 $THIS_DIR/lib/libcommpact.so

# symlink the enclave .so to /tmp
ln -s $THIS_DIR/enclave/lib/enclave.signed.so /tmp/

echo "=========================="
echo "= Downloading OMNet++... ="
echo "=========================="
# download OMNeT++
pushd $THIS_DIR
wget --user-agent='Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0' --header='Referer: https://www.omnetpp.org/component/jdownloads/category/32-release-older-versions?start=10' https://www.omnetpp.org/component/jdownloads/send/32-release-older-versions/2305-omnetpp-50-linux -O omnetpp-5.0.tgz
echo "====================="
echo "= Unpacking OMNet++ ="
echo "====================="
tar -xf omnetpp-5.0.tgz
rm omnetpp-5.0.tgz
echo "===================="
echo "= Building OMNet++ ="
echo "===================="
cd omnetpp-5.0/
source ./setenv -f
./configure
make -j$(nproc)
popd

# check out the sumo and veins submodules
echo "=============================="
echo "= Checking out submodules... ="
echo "=============================="
git submodule init
git submodule update


echo "===================="
echo "= Building SUMO... ="
echo "===================="
# build sumo
pushd $THIS_DIR/plexe-sumo/sumo
git pull
git checkout plexe-2.0
make -f Makefile.cvs
CPPFLAGS="-I/$THIS_DIR/include" ./configure
make -j$(nproc)
popd

# set up PATH so we can find OMNeT++
export PATH=$PATH:$THIS_DIR/omnetpp-5.0/bin


echo "====================="
echo "= Building Veins... ="
echo "====================="
# build veins
pushd $THIS_DIR/plexe-veins
git pull
git checkout plexe-2.0
./configure
make -j$(nproc)
popd
