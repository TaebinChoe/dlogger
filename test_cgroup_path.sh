#!/bin/bash
set -e

echo "=== Meticulous Cgroup Path Test (Direct Background Run) ==="

# 1. Clean up old files
rm -f fine.csv pg.bin test_suite.bin

# Compile dlogger, eaudit and test suite
make clean && make && make kdarshan_test_suite

# 2. Start dlogger in the background
echo "Starting dlogger..."
sudo ./dlogger > dlogger_test.log 2>&1 &
DLOGGER_PID=$!
echo "dlogger started with PID: $DLOGGER_PID"

# Verify dlogger is running and wait for BPF attachment
echo "Waiting for dlogger to compile and start..."
READY=0
for i in {1..30}; do
    if [ ! -d "/proc/$DLOGGER_PID" ]; then
        echo "dlogger process died early!"
        cat dlogger_test.log
        exit 1
    fi
    if grep -q "dlogger is running" dlogger_test.log 2>/dev/null; then
        echo "dlogger is ready!"
        READY=1
        break
    fi
    sleep 1
done

if [ $READY -ne 1 ]; then
    echo "dlogger timed out starting!"
    cat dlogger_test.log
    exit 1
fi

# 3. Run workload directly in the background
echo "Spawning kdarshan_test_suite..."
./kdarshan_test_suite &
TEST_PID=$!
echo "kdarshan_test_suite running with PID: $TEST_PID"

# Wait for the test workload to finish
wait $TEST_PID || true
echo "Workload completed. Waiting for dlogger to flush..."
sleep 2

# 4. Stop dlogger
echo "Stopping dlogger..."
sudo killall -INT dlogger || true
sudo kill -INT $DLOGGER_PID || true
wait $DLOGGER_PID || true
echo "dlogger stopped."

# 5. Analyze the output: fine.csv
echo "=== Analyzing fine.csv ==="
if [ ! -f "fine.csv" ]; then
    echo "FAIL: fine.csv was not generated!"
    exit 1
fi

echo "Header and matching lines in fine.csv:"
head -n 1 fine.csv
grep "session-" fine.csv || echo "No session cgroup path entries in fine.csv"

# 6. Analyze the output: pg.bin
echo "=== Analyzing pg.bin with eaudit ==="
if [ ! -f "pg.bin" ]; then
    echo "FAIL: pg.bin was not generated!"
    exit 1
fi

./eaudit -I pg.bin -P - > parsed_audit.txt
echo "Checking parsed_audit.txt for session cgroup path..."
grep -i "session-" parsed_audit.txt | head -n 10 || echo "FAIL: session cgroup path not found in pg.bin!"

echo "=== Test Completed ==="
if grep -q "session-" fine.csv && grep -q "session-" parsed_audit.txt; then
    echo "SUCCESS: Cgroup path logged and verified in both fine.csv and pg.bin!"
else
    echo "FAILURE: Cgroup path was not captured correctly."
    exit 1
fi
