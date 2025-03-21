#!/bin/bash

# Start Cowrie honeypot
echo "Starting Cowrie Honeypot..."
bin/cowrie start &  # Start Cowrie in the background

# Paths to Cowrie logs
LOG_FILE="var/log/cowrie/cowrie.log"

# Patterns for SQL Injection detection
SQL_PATTERNS=("UNION SELECT" "SELECT * FROM" "DROP TABLE" "INSERT INTO" "OR 1=1" "' OR '" "--" "#")

# Patterns for XSS detection
XSS_PATTERNS=("alert(" "<script>" "<img" "onerror=" "onload=" "document.cookie" "<iframe>")

# Patterns for CSRF detection
CSRF_PATTERNS=("action=" "GET /" "POST /" "delete=" "update=" "id=")

# Function to scan logs for patterns and save to log files
scan_logs() {
    local attack_type="$1"
    local log_line="$2"
    shift 2
    local patterns=("$@")

    # Convert attack_type to lowercase using tr command
    local attack_type_lower=$(echo "$attack_type" | tr '[:upper:]' '[:lower:]')

    for pattern in "${patterns[@]}"; do
        if [[ "$log_line" =~ $pattern ]]; then
            echo "$attack_type Attack Detected: $log_line"
            # Append detected attack to the appropriate log file
            echo "$log_line" >> "var/log/cowrie/${attack_type_lower}_attacks.log"
        fi
    done
}

# Ensure log files exist
mkdir -p var/log/cowrie
touch var/log/cowrie/sql_injection_attacks.log
touch var/log/cowrie/xss_attacks.log
touch var/log/cowrie/csrf_attacks.log

# Monitor logs in real-time
echo "Monitoring logs for SQL Injection, XSS, and CSRF attacks in $LOG_FILE..."
tail -F "$LOG_FILE" | while read -r line; do
    scan_logs "SQL Injection" "$line" "${SQL_PATTERNS[@]}"
    scan_logs "XSS" "$line" "${XSS_PATTERNS[@]}"
    scan_logs "CSRF" "$line" "${CSRF_PATTERNS[@]}"
done

