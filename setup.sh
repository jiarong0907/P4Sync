#!/bin/sh
sudo apt-get update
sudo apt-get install -y automake cmake libjudy-dev libgmp-dev libpcap-dev libboost-dev libboost-test-dev libboost-program-options-dev libboost-filesystem-dev libboost-thread-dev libevent-dev libtool flex bison pkg-config g++ libssl-dev
sudo apt-get install -y cmake g++ git automake libtool libgc-dev bison flex libfl-dev libgmp-dev libboost-dev libboost-iostreams-dev libboost-graph-dev llvm pkg-config python python-scapy python-ipaddr python-ply tcpdump
sudo apt-get install -y doxygen graphviz
sudo apt-get install -y python-pip
sudo pip uninstall cffi
sudo pip install cffi==1.5.2
sudo ln -s /usr/bin/mcs /usr/bin/gmcs

mkdir p4sync
cd p4sync

git clone git://github.com/mininet/mininet
cd mininet
git tag  # list available versions
git checkout -b 2.2.2 2.2.2  # or whatever version you wish to install
cd ..
mininet/util/install.sh -a



git clone https://github.com/protocolbuffers/protobuf.git
cd protobuf
git submodule update --init --recursive
git checkout -b v3.2.0
./autogen.sh
./configure
make -j4
sudo make install
sudo ldconfig # refresh shared library cache.
cd ..



git clone https://github.com/p4lang/behavioral-model.git
cd behavioral-model
git checkout 50d1b9cb11100c8b010f76b9bc2daabd97425f6d
sh travis/install-thrift.sh
sh travis/install-nanomsg.sh
sh travis/install-nnpy.sh
./autogen.sh
./configure --disable-logging-macros --disable-elogger 'CFLAGS=-O3' 'CXXFLAGS=-O3'
make -j4
sudo make install  # if you need to install bmv2
sudo ldconfig
cd ..


git clone --recursive https://github.com/p4lang/p4c.git
cd p4c
git checkout 212b3e131000c0c5cab418b4d6e721828e17eb5d
mkdir build
cd build
cmake .. -DENABLE_EBPF=OFF -DENABLE_P4C_GRAPHS=OFF -DENABLE_P4TEST=OFF -DENABLE_DOCS=OFF
make -j4
#make -j4 check
sudo make install
cd ../../

#For running receiveSwid.py to capture vlan id
sudo pip install pypcap
sudo pip install pycrypto
sudo pip install pycryptodome