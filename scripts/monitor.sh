#!/bin/bash

# ==========================================
# Script Name: monitor.sh
# Project: VantaWire
# Purpose: Basic Intruder Tracker
# ==========================================

LOG_FILE="vanta_log.txt"
TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")

echo "[$TIMESTAMP] VantaWire check initiated..." >> "$LOG_FILE"

# Capture established network connections and save them to the log
netstat -ant | grep ESTABLISHED >> "$LOG_FILE"

echo "[$TIMESTAMP] Check complete. Log saved to $LOG_FILE"
