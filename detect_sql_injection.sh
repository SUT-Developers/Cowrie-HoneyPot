#!/bin/bash

# Path to Cowrie log
LOG_FILE="var/log/cowrie/cowrie.log"

# Patterns for SQL injection
SQL_PATTERNS=("SELECT" "UNION" "DROP" "INSERT" "UPDATE" "--" ";" "' OR '" "OR 1=1" "SLEEP(")

# Scan the log file
echo "Scanning for SQL injection attempts in $LOG_FILE..."
tail -f "$LOG_FILE" | while read -r line; do
    for pattern in "${SQL_PATTERNS[@]}"; do
        if [[ "$line" =~ $pattern ]]; then
            echo "SQL Injection Detected: $line"
            # Optional: Save to a separate log
            echo "$line" >> var/log/cowrie/sql_injections.log
        fi
    done
done

