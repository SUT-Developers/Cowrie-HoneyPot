#!/bin/bash

# Path to Cowrie logs
LOG_FILE="var/log/cowrie/cowrie.log"

# Pattern to detect directory traversal
TRAVERSAL_PATTERN="..\/..\/.."

# Function to scan logs for directory traversal attempts
scan_traversal() {
    local log_line="$1"
    if [[ "$log_line" =~ $TRAVERSAL_PATTERN ]]; then
        echo "Directory Traversal Attack Detected: $log_line"
        # Save to the log file for directory traversal attacks
        echo "$log_line" >> "var/log/cowrie/dir_traversal_attacks.log"
    fi
}

# Monitor logs in real-time for directory traversal attacks
echo "Monitoring for directory traversal attacks..."
tail -F "$LOG_FILE" | while read -r line; do
    scan_traversal "$line"
done

