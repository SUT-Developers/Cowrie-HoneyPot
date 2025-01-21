#!/bin/bash

# File Exfiltration Detection Script for Cowrie Honeypot

LOG_FILE="/Users/abdullah/cowrie/var/log/cowrie/cowrie.log"
ALERT_FILE="/Users/abdullah/cowrie/var/log/cowrie/file_exfil_alerts.log"
EMAIL_ALERT="your-email@example.com"

# Function to detect suspicious file access attempts
function detect_file_exfiltration() {
    echo "Monitoring for file exfiltration attempts..."
    tail -f $LOG_FILE | while read -r line; do
        if [[ "$line" =~ "cat" || "$line" =~ "scp" || "$line" =~ "wget" || "$line" =~ "curl" ]]; then
            FILE=$(echo "$line" | grep -oP '(?<=cat\s|scp\s|wget\s|curl\s).*')
            echo -e "\033[1;31m[ALERT]\033[0m File Exfiltration Attempt Detected: $line"
            echo "File Requested: $FILE"
            echo "[ALERT] File Exfiltration Attempt Detected: $line" | tee -a $ALERT_FILE
            echo "File Exfiltration Attempt Detected: $line" | mail -s "Cowrie File Exfiltration Alert" $EMAIL_ALERT
        fi
    done
}

# Run the file exfiltration detection function
detect_file_exfiltration
