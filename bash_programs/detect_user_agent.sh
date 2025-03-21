#!/bin/bash

# Path to Cowrie logs
LOG_FILE="/var/log/cowrie/cowrie.log"

# List of suspicious User-Agent patterns
SUSPICIOUS_UA=("Mozilla/5.0 (Windows NT" "curl" "wget" "python-requests" "libwww-perl" "bot")

# Function to scan logs for suspicious User-Agent strings
scan_user_agent() {
    local log_line="$1"
    for ua in "${SUSPICIOUS_UA[@]}"; do
        if [[ "$log_line" =~ $ua ]]; then
            echo "Suspicious User-Agent Detected: $log_line"
            # Log suspicious User-Agent to the log file
            echo "$log_line" >> "/var/log/cowrie/suspicious_user_agents.log"
        fi
    done
}

# Monitor logs in real-time for suspicious User-Agents
echo "Monitoring for suspicious User-Agent strings..."
tail -F "$LOG_FILE" | while read -r line; do
    scan_user_agent "$line"
done
