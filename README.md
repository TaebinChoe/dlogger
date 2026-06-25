

---

```markdown
# dlogger - Unified Kernel & Userspace I/O Logger

`dlogger` is a unified, high-performance kernel/userspace logging tool that combines the system call auditing features of `eaudit` with the application-level I/O characterization of `kdarshan`. 

It filters out its own execution automatically via descendant self-exclusion and enriches every process log entry with Process ID, Cgroup ID, Cgroup Path, and Task Start Time.

---

## Output Logs
1. **`pg.bin`**: `eaudit`-style binary capture file containing enriched process info (PID, Cgroup, Cgroup Path, Start Time). Inspect using the offline parser: `./eaudit -I pg.bin -P -`.
2. **`fine.csv`**: DXT-style CSV file containing read/write metrics (PID, Cgroup, Cgroup Path, Start Time, Offset, Length, Timestamps, Filename), filtered by `FINE_EXCLUDE_PATH`.

---

## Installation & Deployment Guide (A to Z)

Follow these steps in order to install dependencies, compile the source code, and run `dlogger` inside your local directory (`~/app/dlogger`).

### 1. Install Toolchains and Kernel Packages
First, set up the basic build tools, compiler collections, and necessary kernel header files corresponding to your running kernel version.

```bash
sudo apt update
sudo apt install -y linux-tools-common linux-tools-$(uname -r) linux-headers-$(uname -r)

```

### 2. Build and Install BCC (BPF Compiler Collection) From Source

Since some Ubuntu repositories might lack or contain outdated `libbcc-dev` packages, we compile the latest stable BCC framework directly from the source to guarantee `libbcc.so.0` runtime compatibility.

```bash
# Install BCC build-time dependencies
sudo apt install -y zip bison build-essential cmake flex git libedit-dev \
  libllvm14 llvm-14-dev libclang-14-dev python3 zlib1g-dev libelf-dev libfl-dev \
  python3-setuptools liblzma-dev libdebuginfod-dev

# Clone and compile BCC
mkdir -p ~/app/src && cd ~/app/src
git clone [https://github.com/iovisor/bcc.git](https://github.com/iovisor/bcc.git)
mkdir -p bcc/build && cd bcc/build
cmake ..
make -j$(nproc)
sudo make install

# Update system dynamic linker cache so libbcc.so.0 is globally recognized
sudo ldconfig

```

### 3. Compile Static `libbpf`

`dlogger` requires linking against a static `libbpf` instance (v1.0 or higher).

```bash
cd ~/app
git clone [https://github.com/libbpf/libbpf.git](https://github.com/libbpf/libbpf.git)
cd libbpf/src
make BUILD_STATIC_ONLY=y DESTDIR=$(pwd)/install install

```

### 4. Build `dlogger` and the Offline Parser

Navigate to your local `dlogger` directory, clean up old artifacts, and compile both the unified tracer and the binary log parser.

```bash
cd ~/app/dlogger

# Clean stale object files
make clean

# Compile the BPF bytecode and the main dlogger executable
make LIBBPF_DIR=~/app/libbpf/src/install BPFTOOL=/usr/lib/linux-tools/$(uname -r)/bpftool

# Compile the eaudit offline parser binary
g++ -g -std=c++2a -Wall -O2 -DREC_ONLY_HOST -Ilib/ -c eaudit.C -o eaudit.o
g++ -o eaudit eaudit.o eauditd.o eParser.o prthelper.o eConsumer.o ePrinter.o eRecorder.o RecOnlyHost.o -lbcc -lelf -lz -lpthread

```

> *Note: You might encounter several compiler warnings regarding `loop not unrolled` or `output may be truncated`. These are expected optimization behaviors and can safely be ignored as long as the binaries are generated successfully.*

---

## Verification & Execution Guide

### 1. Run `dlogger` and Trigger Test I/O

Make sure your exclude pathways are configured properly inside `dlogger.conf` (loaded automatically from the current directory). Launch `dlogger` with root privileges in the background, issue dummy file writes, and cleanly terminate using `SIGINT`.

```bash
cd ~/app/dlogger

# Start dlogger as a background task
sudo ./dlogger &
DLOGGER_PID=$!
sleep 2

# Generate sample I/O workload (10MB block write)
dd if=/dev/zero of=test_dd.bin bs=1M count=10
sync

# Gracefully terminate dlogger to trigger final buffer flush
sudo kill -2 $DLOGGER_PID
sleep 2

```

### 2. Verify Generated Logs

* **Inspect Characterization Metrics (`fine.csv`):**
```bash
cat fine.csv

```


*(Expect structured CSV trace headers and metrics mapping Offset, Length, and Timestamps).*
* **Parse Binary Capture File (`pg.bin`):**
```bash
./eaudit -I pg.bin -P -

```


*(Expect clean text translations mapping `pid=... cgroup=... cgroup_path=... start_time=...` details).*
* **Verify Descendant Self-Exclusion:**
Ensure `dlogger` successfully avoided capturing its own background execution trail.
```bash
grep "$DLOGGER_PID" fine.csv
./eaudit -I pg.bin -P - 2>&1 | grep "pid=$DLOGGER_PID"

```


*(Expect no matching outputs to print, validating full descendant exclusion).*

```

```
