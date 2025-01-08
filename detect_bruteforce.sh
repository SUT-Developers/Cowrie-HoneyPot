#!/bin/bash

# Path to Cowrie logs
LOG_FILE="var/log/cowrie/cowrie.log"

# Store failed login attempts in a temporary file
TEMP_FILE="/tmp/bruteforce_attempts.txt"

# Pattern for failed login attempts (customize this based on your Cowrie configuration)
FAILED_PATTERN="Failed login for"

# Function to scan logs for brute force attempts
scan_bruteforce() {
    local log_line="$1"
    if [[ "$log_line" =~ $FAILED_PATTERN ]]; then
        echo "$log_line"
        # Extract the IP address of the failed attempt
        ip_address=$(echo "$log_line" | grep -oP '(?<=from )(\d+\.\d+\.\d+\.\d+)')
        echo "$ip_address" >> "$TEMP_FILE"
    fi
}

# Monitor logs in real-time and detect brute force attempts
echo "Monitoring for brute force attacks..."
tail -F "$LOG_FILE" | while read -r line; do
    scan_bruteforce "$line"
done

# Check if there are more than 5 failed attempts from the same IP within a short period
while :; do
    for ip in $(cat "$TEMP_FILE" | sort | uniq -c | awk '$1 > 5 {print $2}'); do
        echo "Brute force detected from IP: $ip"
    done
    sleep 10
done

