#!/bin/bash

# Path to Cowrie logs
LOG_FILE="var/log/cowrie/cowrie.log"

# List of suspicious commands that might indicate RCE
RCE_COMMANDS=("nc -e" "bash -i" "sh -i" "wget" "curl" "perl -e")

# Function to scan logs for remote command execution attempts
scan_rce() {
    local log_line="$1"
    for cmd in "${RCE_COMMANDS[@]}"; do
        if [[ "$log_line" =~ $cmd ]]; then
            echo "Remote Command Execution Attempt Detected: $log_line"
            # Log the detected RCE attempt
            echo "$log_line" >> "var/log/cowrie/rce_attacks.log"
        fi
    done
}

# Monitor logs in real-time for RCE attempts
echo "Monitoring for remote command execution attempts..."
tail -F "$LOG_FILE" | while read -r line; do
    scan_rce "$line"
done

