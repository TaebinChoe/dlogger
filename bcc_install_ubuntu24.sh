# this script borrows almost verbatim from
# https://github.com/iovisor/bcc/blob/master/INSTALL.md#ubuntu---source but
# with some better error reporting.

fatal() {
  echo "BCC installation failed at the following step: $1"
  exit 1
}

sudo apt update || fatal "apt update"
sudo apt install -y zip bison build-essential cmake flex git libedit-dev \
  libllvm18 llvm-18-dev libclang-18-dev python3 zlib1g-dev libelf-dev libfl-dev \
  python3-setuptools liblzma-dev libdebuginfod-dev arping netperf iperf \
  libpolly-18-dev \
  || fatal "apt install (of required development packages)"
mkdir src || fatal "mkdir"
cd src
git clone https://github.com/iovisor/bcc.git || fatal "cloning BCC source from iovisor"
mkdir bcc/build; cd bcc/build 
cmake .. || fatal "cmake"
make || fatal "Building BCC from source"
sudo make install || fatal "installing BCC"
cmake -DPYTHON_CMD=python3 .. || fatal "building python3 bindings"
pushd src/python/
( make && sudo make install ) || fatal "installing python bindings"
