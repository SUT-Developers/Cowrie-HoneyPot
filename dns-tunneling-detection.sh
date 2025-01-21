#!/bin/bash

# DNS Tunneling Detection Script for Cowrie Honeypot

LOG_FILE="/Users/abdullah/cowrie/var/log/cowrie/cowrie.log"
ALERT_FILE="/Users/abdullah/cowrie/var/log/cowrie/dns_tunnel_alerts.log"
EMAIL_ALERT="your-email@example.com"

# Function to detect suspicious DNS queries
function detect_dns_tunneling() {
    echo "Monitoring for DNS tunneling attempts..."
    tail -f $LOG_FILE | while read -r line; do
        if [[ "$line" =~ "nslookup" || "$line" =~ "dig" || "$line" =~ "host" ]]; then
            echo "[ALERT] Potential DNS Tunneling Detected: $line" | tee -a $ALERT_FILE
            echo "Potential DNS Tunneling Detected: $line" | mail -s "Cowrie DNS Tunneling Alert" $EMAIL_ALERT
        fi
    done
}

# Run the DNS tunneling detection function
detect_dns_tunneling
