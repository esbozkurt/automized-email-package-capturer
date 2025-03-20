#!/bin/bash

# Exit on any error
set -e

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

# Create installation directory
install_dir="/opt/email-monitor"
mkdir -p "$install_dir"

# Copy files
cp main.py "$install_dir/"
cp requirements.txt "$install_dir/"

# Install dependencies
pip3 install -r requirements.txt

# Copy and enable service
cp email-monitor.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable email-monitor.service
systemctl start email-monitor.service

echo "Installation complete. Service is running."
echo "Check status with: systemctl status email-monitor"
echo "View logs with: journalctl -u email-monitor -f"