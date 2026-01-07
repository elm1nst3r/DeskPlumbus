#!/bin/bash
# WiFi Desk Plumbus - Systemd Service Installation Script
# This script installs and enables the Plumbus service to auto-start on boot

set -e

echo "=========================================="
echo "WiFi Desk Plumbus Service Installation"
echo "=========================================="
echo ""

# Get current user and project directory
CURRENT_USER=$(whoami)
PROJECT_DIR=$(pwd)

echo "User: $CURRENT_USER"
echo "Project Directory: $PROJECT_DIR"
echo ""

# Check if we're in the right directory
if [ ! -f "run.py" ]; then
    echo "Error: run.py not found. Please run this script from the DeskPlumbus project directory."
    exit 1
fi

# Create service file from template
echo "Creating systemd service file..."
sed -e "s|{USER}|$CURRENT_USER|g" \
    -e "s|{PROJECT_DIR}|$PROJECT_DIR|g" \
    plumbus.service > plumbus.service.tmp

# Install service file
echo "Installing service file to /etc/systemd/system/..."
sudo cp plumbus.service.tmp /etc/systemd/system/plumbus.service
rm plumbus.service.tmp

# Set correct permissions
sudo chmod 644 /etc/systemd/system/plumbus.service

# Configure sudo permissions for system commands
echo "Configuring sudo permissions for system commands..."
SUDOERS_FILE="/etc/sudoers.d/plumbus"
sudo tee "$SUDOERS_FILE" > /dev/null <<EOF
# WiFi Desk Plumbus - Allow web interface to manage system
$CURRENT_USER ALL=(ALL) NOPASSWD: /sbin/reboot
$CURRENT_USER ALL=(ALL) NOPASSWD: /sbin/shutdown
$CURRENT_USER ALL=(ALL) NOPASSWD: /sbin/ip
$CURRENT_USER ALL=(ALL) NOPASSWD: /sbin/iw
$CURRENT_USER ALL=(ALL) NOPASSWD: /usr/bin/apt-get
$CURRENT_USER ALL=(ALL) NOPASSWD: /usr/sbin/ufw
EOF

sudo chmod 440 "$SUDOERS_FILE"

# Reload systemd daemon
echo "Reloading systemd daemon..."
sudo systemctl daemon-reload

# Enable service to start on boot
echo "Enabling Plumbus service to start on boot..."
sudo systemctl enable plumbus.service

# Ask if user wants to start the service now
echo ""
read -p "Do you want to start the Plumbus service now? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Starting Plumbus service..."
    sudo systemctl start plumbus.service
    sleep 2
    sudo systemctl status plumbus.service --no-pager
fi

echo ""
echo "=========================================="
echo "Installation Complete!"
echo "=========================================="
echo ""
echo "Service commands:"
echo "  Start:   sudo systemctl start plumbus"
echo "  Stop:    sudo systemctl stop plumbus"
echo "  Restart: sudo systemctl restart plumbus"
echo "  Status:  sudo systemctl status plumbus"
echo "  Logs:    sudo journalctl -u plumbus -f"
echo ""
echo "The Plumbus service will automatically start on system boot."
echo ""
