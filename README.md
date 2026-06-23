# dlogger - Unified Kernel & Userspace I/O Logger

`dlogger` is a unified, high-performance kernel/userspace logging tool that combines the system call auditing features of `eaudit` with the application-level I/O characterization of `kdarshan`.

It produces two distinct outputs, filters out its own execution automatically via descendant self-exclusion, and enriches every process log entry with Process ID, Cgroup ID, Cgroup Path, and task Start Time.

---

## Output Logs
1.  **`pg.bin`**: `eaudit`-style binary capture file containing enriched process info (PID, Cgroup, Cgroup Path, Start Time). Can be inspected using the offline parser: `./eaudit -I pg.bin -P -`.
2.  **`fine.csv`**: DXT-style CSV file containing read/write metrics (PID, Cgroup, Cgroup Path, Start Time, Offset, Length, Timestamps, Filename), filtered by `FINE_EXCLUDE_PATH`.

---

## Configuring Output Paths

By default, `dlogger` writes `fine.csv` and `pg.bin` to the current working directory. You can designate custom output paths using either environment variables or the configuration file (`dlogger.conf`).

### Method 1: Environment Variables (Precedence)
Specify the environment variables when running `dlogger`:
```bash
sudo env DLOGGER_CSV_PATH=/path/to/output.csv DLOGGER_BIN_PATH=/path/to/output.bin ./dlogger
```

### Method 2: Configuration Settings (`dlogger.conf`)
Add these options directly to your config file:
```ini
FINE_CSV_PATH = /path/to/output.csv
PG_BIN_PATH = /path/to/output.bin
```

---

## Quick Start Guide (Copy & Paste)

Follow these steps in order to install, compile, run, and verify `dlogger`.

### 1. Install System Dependencies
Run the following commands to install compilation tools, kernel tracing libraries, and `libbcc` C++ dependencies:
```bash
sudo apt-get update
sudo apt-get install -y clang llvm libelf-dev zlib1g-dev make gcc pkg-config git libbcc-dev
sudo apt-get install -y linux-tools-common linux-tools-$(uname -r)
```

### 2. Compile static `libbpf`
`dlogger` links with static `libbpf` (version 1.0 or higher). If you have not compiled it already:
```bash
cd /home/bigdatalab/tchoe
git clone https://github.com/libbpf/libbpf.git
cd libbpf/src
make BUILD_STATIC_ONLY=y DESTDIR=$(pwd)/install install
```

### 3. Build `dlogger` and the Offline Parser
Navigate to the `dlogger` source directory, clean up any stale artifacts, and build both the unified tracer and offline parser:
```bash
cd /home/bigdatalab/tchoe/dlogger

# Clean old object files
make clean

# Compile the BPF bytecode and binary executable
make LIBBPF_DIR=/home/bigdatalab/tchoe/libbpf/src/install BPFTOOL=/usr/lib/linux-tools/$(uname -r)/bpftool

# Compile the eaudit offline parser binary
g++ -g -std=c++2a -Wall -O2 -DREC_ONLY_HOST -Ilib/ -c eaudit.C -o eaudit.o
g++ -o eaudit eaudit.o eauditd.o eParser.o prthelper.o eConsumer.o ePrinter.o eRecorder.o RecOnlyHost.o -lbcc -lelf -lz -lpthread
```

### 4. Run `dlogger` and Trigger test I/O
Configure your exclude paths in `dlogger.conf` (which is loaded automatically from the current directory, `/etc/dlogger.conf`, or can be passed as a command-line argument). Run `dlogger` with root privileges in the background, trigger some file I/O operations, and stop the logger cleanly using `SIGINT`:
```bash
cd /home/bigdatalab/tchoe/dlogger

# Edit the dlogger.conf configuration file:
# vi dlogger.conf

# Start dlogger as a background task (automatically loads dlogger.conf)
sudo ./dlogger &
DLOGGER_PID=$!
sleep 2

# Run file I/O operations (tracked)
dd if=/dev/zero of=test_dd.bin bs=1M count=10
sync

# Stop dlogger gracefully (triggers final flush and log generation)
sudo kill -2 $DLOGGER_PID
sleep 2
```

### 5. Verify the Generated Logs
Inspect the two generated files to verify they contain correct, enriched process metadata:

*   **Inspect `fine.csv` (DXT CSV):**
	```bash
	cat fine.csv
	```
	*(Expect headers and read/write CSV entries with PID, Cgroup_ID, Cgroup_Path, and Start_Time).*

*   **Parse `pg.bin` using `./eaudit` (Binary Audit Capture):**
	```bash
	./eaudit -I pg.bin -P -
	```
	*(Expect formatted system call entries displaying `pid=... cgroup=... cgroup_path=... start_time=...` details).*

*   **Verify Self-Exclusion:**
	Verify that no records match the PID of `dlogger` or its children:
	```bash
	grep "$DLOGGER_PID" fine.csv
	./eaudit -I pg.bin -P - 2>&1 | grep "pid=$DLOGGER_PID"
	```
	*(Expect no matching lines to print, confirming descendant self-exclusion).*
