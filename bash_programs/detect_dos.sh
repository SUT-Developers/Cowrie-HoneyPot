#!/bin/bash

# Path to Cowrie logs
LOG_FILE="var/log/cowrie/cowrie.log"

# Store request counts per IP in a temporary file
TEMP_FILE="/tmp/dos_requests.txt"

# Threshold for request count
THRESHOLD=100

# Create an empty temp file if it doesn't exist
touch "$TEMP_FILE"

# Function to scan logs for repeated SSH connection attempts
scan_dos() {
    local log_line="$1"
    # Match connection attempts, and extract the IP address (adjust the pattern if necessary)
    ip_address=$(echo "$log_line" | grep -oE 'Connection from [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | awk '{print $3}')
    if [ -n "$ip_address" ]; then
        echo "$ip_address" >> "$TEMP_FILE"
    fi
}

# Monitor logs in real-time for connection attempts
echo "Monitoring for Denial of Service (DoS) attacks..."
tail -F "$LOG_FILE" | while read -r line; do
    scan_dos "$line"
done &  # Run the above monitoring process in the background

# Check if any IP exceeds the threshold (e.g., 100 requests in a short period)
while :; do
    for ip in $(cat "$TEMP_FILE" | sort | uniq -c | awk '$1 > '$THRESHOLD' {print $2}'); do
        echo "DoS attack detected from IP: $ip"
    done
    sleep 10
done
