#!/bin/bash

# ==========================================
# Script Name: monitor.sh
# Project: VantaWire
# Purpose: Basic Intruder Tracker
# ==========================================

LOG_FILE="vanta_log.txt"
# Define safe IP addresses
SAFE_IPS=("127.0.0.1" "192.168.1.1")
TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")

echo "[$TIMESTAMP] VantaWire check initiated..." >> "$LOG_FILE"

# Capture established network connections and save them to the log
# Refined: Check for connections on Port 22 (SSH) specifically
# We look for ESTABLISHED connections and filter for port 22
echo "--- Scanning for SSH (Port 22) activity ---" >> "$LOG_FILE"
netstat -ant | grep ':22' | grep ESTABLISHED >> "$LOG_FILE"

# Refined: Check for connections on Ports 80/443 (Web)
echo "--- Scanning for Web (Port 80/443) activity ---" >> "$LOG_FILE"
netstat -ant | grep -E ':80|:443' | grep ESTABLISHED >> "$LOG_FILE"

echo "[$TIMESTAMP] Check complete. Log saved to $LOG_FILE"

if [ ! -z "$suspicious" ]; then
    echo "!!! WARNING: Unusual activity detected !!!" >> "$LOG_FILE"
    echo "$suspicious" >> "$LOG_FILE"
fi
