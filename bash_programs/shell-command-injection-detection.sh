#!/bin/bash

# Shell Command Injection Detection Script for Cowrie Honeypot

LOG_FILE="/Users/abdullah/cowrie/var/log/cowrie/cowrie.log"
ALERT_FILE="/Users/abdullah/cowrie/var/log/cowrie/shell_injection_alerts.log"
EMAIL_ALERT="your-email@example.com"

# Function to detect shell command injection attempts
function detect_shell_injection() {
    echo "Monitoring for shell command injection attempts..."
    tail -f $LOG_FILE | while read -r line; do
        if [[ "$line" =~ "; " || "$line" =~ "&& " || "$line" =~ "\|\| " || "$line" =~ ">/dev/null" ]]; then
            COMMAND=$(echo "$line" | grep -oP '(?<=: ).*')
            echo -e "\033[1;31m[ALERT]\033[0m Shell Command Injection Detected: $line"
            echo "Suspicious Command: $COMMAND"
            echo "[ALERT] Shell Command Injection Attempt Detected: $line" | tee -a $ALERT_FILE
            echo "Shell Command Injection Attempt Detected: $line" | mail -s "Cowrie Shell Command Injection Alert" $EMAIL_ALERT
        fi
    done
}

# Run the shell command injection detection function
detect_shell_injection
