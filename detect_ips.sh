#!/bin/bash

# Define the path to the Cowrie log file and the output log file
LOG_FILE="/Users/abdullah/cowrie/var/log/cowrie/ip.log"
OUTPUT_FILE="IP.logs"

# Ensure the output file exists and is writable
touch "$OUTPUT_FILE"

# Monitor the log file for new entries

tail -F "$LOG_FILE" | while read -r line; do
    # Extract IP addresses from lines that indicate a connection
    if echo "$line" | grep -E -o "([0-9]{1,3}\.){3}[0-9]{1,3}" > /dev/null; then
        ip=$(echo "$line" | grep -E -o "([0-9]{1,3}\.){3}[0-9]{1,3}")

        # Check if the IP is already logged
        if ! grep -Fxq "$ip" "$OUTPUT_FILE"; then
            echo "$ip" >> "$OUTPUT_FILE"
            echo "[INFO] Logged new IP: $ip"
        fi
    fi
done

