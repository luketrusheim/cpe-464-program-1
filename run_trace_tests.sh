#!/bin/bash

# Optional: clear screen and start fresh
clear

echo "Running trace tests..."

# For each .pcap file in the current directory
for pcap_file in *.pcap; do
    # Strip the extension to get the base name
    base_name="${pcap_file%.pcap}"

    # Output file to compare against
    expected_output="${base_name}.out"

    # Temp file to hold current trace output
    actual_output="trace_tmp_output.txt"

    # Run the trace command
    ./trace "$pcap_file" > "$actual_output"

    # Compare with expected output
    if diff -q "$actual_output" "$expected_output" > /dev/null; then
        echo "[PASS] $pcap_file matches $expected_output"
    else
        echo "[FAIL] $pcap_file differs from $expected_output"
        echo "Use 'diff trace_tmp_output.txt $expected_output' to compare"
    fi
done

# Optional: clean up
rm -f trace_tmp_output.txt
