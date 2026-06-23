#!/bin/bash

# Clean up any previous logs
rm -f test_suite_run_posix.log test_suite_run_dxt.log test_suite.bin

# Compile test suite if needed
make kdarshan_test_suite

# ========================================================
# Phase 1: Test Standard POSIX Counter Formatting
# ========================================================
echo "=== Phase 1: Tracing POSIX Counters ==="
./kdarshan_test_suite &
PID=$!
echo "Started kdarshan_test_suite (PID: $PID)"

# Start kdarshan tracing this PID (without -d, standard POSIX counters format)
sudo ./kdarshan -p $PID > test_suite_run_posix.log 2>&1 &
KPID=$!
echo "Started kdarshan tracer (PID: $KPID)"

# Wait for test program to complete
wait $PID
echo "kdarshan_test_suite finished."

# Let kdarshan flush and stop it
sleep 1
sudo kill -INT $KPID
wait $KPID
echo "kdarshan tracer stopped."

# ========================================================
# Phase 2: Test DXT Tracing Formatting
# ========================================================
echo "=== Phase 2: Tracing DXT events ==="
rm -f test_suite.bin
./kdarshan_test_suite &
PID=$!
echo "Started kdarshan_test_suite (PID: $PID)"

# Start kdarshan tracing this PID (with -d, DXT format)
sudo ./kdarshan -p $PID -d > test_suite_run_dxt.log 2>&1 &
KPID=$!
echo "Started kdarshan tracer (PID: $KPID)"

# Wait for test program to complete
wait $PID
echo "kdarshan_test_suite finished."

# Let kdarshan flush and stop it
sleep 1
sudo kill -INT $KPID
wait $KPID
echo "kdarshan tracer stopped."

echo "--------------------------------------------------------"
echo "Captured POSIX Counter Log Output:"
cat test_suite_run_posix.log
echo "--------------------------------------------------------"
echo "Captured DXT Log Output:"
cat test_suite_run_dxt.log
echo "--------------------------------------------------------"

# Test Assertions
exit_code=0

assert_counter() {
    local counter_name="$1"
    local expected_val="$2"
    # Find tab-separated value in column 5
    local actual_val=$(grep -P "POSIX\t-1\t\d+\t${counter_name}\t" test_suite_run_posix.log | awk -F'\t' '{print $5}' | xargs)
    if [ "$actual_val" = "$expected_val" ]; then
        echo -e "\e[32m✓ ${counter_name}: Expected ${expected_val}, got ${actual_val}.\e[0m"
    else
        echo -e "\e[31m✗ ${counter_name}: Expected ${expected_val}, but got '${actual_val}'.\e[0m"
        exit_code=1
    fi
}

echo "Running assertions on POSIX metrics..."
assert_counter "POSIX_OPENS" "2" # open() + dup()
assert_counter "POSIX_READS" "1"
assert_counter "POSIX_WRITES" "4"
assert_counter "POSIX_SEEKS" "2"
assert_counter "POSIX_BYTES_READ" "10"
assert_counter "POSIX_BYTES_WRITTEN" "56"
assert_counter "POSIX_MEM_NOT_ALIGNED" "1"
assert_counter "POSIX_FILE_NOT_ALIGNED" "3"
assert_counter "POSIX_SEQ_WRITES" "1"
assert_counter "POSIX_CONSEC_WRITES" "1"
assert_counter "POSIX_RW_SWITCHES" "2"
assert_counter "POSIX_FSYNCS" "1"
assert_counter "POSIX_FDSYNCS" "1"
assert_counter "POSIX_STATS" "1"
assert_counter "POSIX_DUPS" "1"
assert_counter "POSIX_MMAPS" "1"

# Verify DXT entries
dxt_w_count=$(grep -E "^\s*X_POSIX\s+\S+\s+write\s+" test_suite_run_dxt.log | wc -l)
dxt_r_count=$(grep -E "^\s*X_POSIX\s+\S+\s+read\s+" test_suite_run_dxt.log | wc -l)

if [ "$dxt_w_count" -eq 4 ]; then
    echo -e "\e[32m✓ DXT Write Traces: Expected 4, got ${dxt_w_count}.\e[0m"
else
    echo -e "\e[31m✗ DXT Write Traces: Expected 4, but got ${dxt_w_count}.\e[0m"
    exit_code=1
fi

if [ "$dxt_r_count" -eq 1 ]; then
    echo -e "\e[32m✓ DXT Read Traces: Expected 1, got ${dxt_r_count}.\e[0m"
else
    echo -e "\e[31m✗ DXT Read Traces: Expected 1, but got ${dxt_r_count}.\e[0m"
    exit_code=1
fi

if [ $exit_code -eq 0 ]; then
    echo -e "\n\e[32mALL TESTS PASSED SUCCESSFULLY!\e[0m"
else
    echo -e "\n\e[31mSOME TESTS FAILED!\e[0m"
fi

exit $exit_code
