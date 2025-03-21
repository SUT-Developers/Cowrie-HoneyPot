#!/bin/bash

# Define the honeypot port
HONEYPOT_PORT=2222
LOG_FILE="honeypot_traffic.log"

echo "Monitoring traffic on port $HONEYPOT_PORT..."
echo "Captured packets will be logged to $LOG_FILE"

# Use tcpdump with the lo0 interface for local traffic
sudo tcpdump -i lo0 port $HONEYPOT_PORT -w honeypot_traffic.pcap &
PID=$!

echo "Press [CTRL+C] to stop monitoring."

# Wait for user to terminate
trap "echo Stopping packet capture...; sudo kill $PID; exit" INT
wait

