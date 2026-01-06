#!/bin/bash

###############################################################################
# WiFi Desk Plumbus - Automated Installation Script
#
# This script automates the complete setup process for the WiFi Desk Plumbus
# on Raspberry Pi Zero W / Zero 2 W
#
# Usage: chmod +x install.sh && ./install.sh
###############################################################################

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Project settings
PROJECT_NAME="WiFi Desk Plumbus"
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$PROJECT_DIR/venv"
SERVICE_NAME="plumbus"
SERVICE_FILE="plumbus.service"
WIFI_INTERFACE="wlan0"

###############################################################################
# Helper Functions
###############################################################################

print_banner() {
    echo -e "${BLUE}"
    cat << "EOF"
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║    ██████╗ ██╗     ██╗   ██╗███╗   ███╗██████╗ ██╗   ██╗ ║
    ║    ██╔══██╗██║     ██║   ██║████╗ ████║██╔══██╗██║   ██║ ║
    ║    ██████╔╝██║     ██║   ██║██╔████╔██║██████╔╝██║   ██║ ║
    ║    ██╔═══╝ ██║     ██║   ██║██║╚██╔╝██║██╔══██╗██║   ██║ ║
    ║    ██║     ███████╗╚██████╔╝██║ ╚═╝ ██║██████╔╝╚██████╔╝ ║
    ║    ╚═╝     ╚══════╝ ╚═════╝ ╚═╝     ╚═╝╚═════╝  ╚═════╝  ║
    ║                                                           ║
    ║          Automated Installer - Everyone Has One!         ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "\n${BLUE}==>${NC} $1"
}

check_root() {
    if [[ $EUID -eq 0 ]]; then
        log_error "This script should NOT be run as root!"
        log_info "Run as regular user (pi), sudo will be used when needed"
        exit 1
    fi
}

check_raspberry_pi() {
    if [[ ! -f /proc/device-tree/model ]]; then
        log_warn "Could not detect Raspberry Pi model"
        log_warn "This script is designed for Raspberry Pi, but will continue anyway"
        return
    fi

    local model=$(cat /proc/device-tree/model)
    log_info "Detected: $model"
}

check_wifi_interface() {
    if ! ip link show "$WIFI_INTERFACE" &> /dev/null; then
        log_error "WiFi interface $WIFI_INTERFACE not found!"
        log_info "Available interfaces:"
        ip link show | grep -E "^[0-9]" | cut -d: -f2
        exit 1
    fi
    log_info "WiFi interface $WIFI_INTERFACE found"
}

check_monitor_mode_support() {
    log_step "Checking monitor mode support..."

    if ! iw list | grep -q "monitor"; then
        log_error "WiFi interface does not support monitor mode!"
        log_info "Please ensure you have updated Raspberry Pi OS and firmware"
        log_info "Run: sudo apt update && sudo apt full-upgrade"
        exit 1
    fi

    log_info "Monitor mode is supported"
}

###############################################################################
# Installation Steps
###############################################################################

step_system_update() {
    log_step "Step 1/8: Updating system packages..."

    sudo apt update
    log_info "System package list updated"
}

step_install_dependencies() {
    log_step "Step 2/8: Installing system dependencies..."

    local packages=(
        "python3"
        "python3-pip"
        "python3-venv"
        "iw"
        "wireless-tools"
        "tcpdump"
        "git"
    )

    log_info "Installing: ${packages[*]}"
    sudo apt install -y "${packages[@]}"

    log_info "System dependencies installed"
}

step_create_venv() {
    log_step "Step 3/8: Creating Python virtual environment..."

    if [[ -d "$VENV_DIR" ]]; then
        log_warn "Virtual environment already exists, removing..."
        rm -rf "$VENV_DIR"
    fi

    python3 -m venv "$VENV_DIR"
    log_info "Virtual environment created at $VENV_DIR"
}

step_install_python_packages() {
    log_step "Step 4/8: Installing Python packages..."

    source "$VENV_DIR/bin/activate"

    # Upgrade pip
    pip install --upgrade pip

    # Install requirements
    if [[ -f "$PROJECT_DIR/requirements.txt" ]]; then
        pip install -r "$PROJECT_DIR/requirements.txt"
        log_info "Python packages installed"
    else
        log_error "requirements.txt not found!"
        exit 1
    fi

    deactivate
}

step_create_directories() {
    log_step "Step 5/8: Creating project directories..."

    mkdir -p "$PROJECT_DIR/data"
    mkdir -p "$PROJECT_DIR/logs"
    mkdir -p "$PROJECT_DIR/data/exports"
    mkdir -p "$PROJECT_DIR/data/backups"

    log_info "Project directories created"
}

step_configure_monitor_mode() {
    log_step "Step 6/8: Configuring WiFi monitor mode..."

    log_info "Testing monitor mode setup..."

    # Try to enable monitor mode temporarily
    if sudo ip link set "$WIFI_INTERFACE" down 2>/dev/null && \
       sudo iw dev "$WIFI_INTERFACE" set type monitor 2>/dev/null && \
       sudo ip link set "$WIFI_INTERFACE" up 2>/dev/null; then
        log_info "Monitor mode test successful"

        # Return to managed mode
        sudo ip link set "$WIFI_INTERFACE" down
        sudo iw dev "$WIFI_INTERFACE" set type managed
        sudo ip link set "$WIFI_INTERFACE" up
    else
        log_warn "Could not enable monitor mode automatically"
        log_warn "You may need to configure this manually"
    fi
}

step_install_service() {
    log_step "Step 7/8: Installing systemd service..."

    if [[ ! -f "$PROJECT_DIR/$SERVICE_FILE" ]]; then
        log_error "Service file $SERVICE_FILE not found!"
        exit 1
    fi

    # Update service file with correct paths
    local service_content=$(cat "$PROJECT_DIR/$SERVICE_FILE")
    service_content="${service_content//\{PROJECT_DIR\}/$PROJECT_DIR}"
    service_content="${service_content//\{USER\}/$USER}"

    # Write updated service file
    echo "$service_content" | sudo tee "/etc/systemd/system/$SERVICE_NAME.service" > /dev/null

    # Reload systemd
    sudo systemctl daemon-reload

    # Enable service
    sudo systemctl enable "$SERVICE_NAME.service"

    log_info "Systemd service installed and enabled"
}

step_configure_firewall() {
    log_step "Step 8/8: Configuring firewall..."

    if command -v ufw &> /dev/null; then
        # Allow Flask port
        sudo ufw allow 5000/tcp comment "Plumbus Web Interface"

        # Enable firewall if not already enabled
        if ! sudo ufw status | grep -q "Status: active"; then
            log_info "Enabling UFW firewall..."
            echo "y" | sudo ufw enable
        fi

        log_info "Firewall configured (port 5000 allowed)"
    else
        log_warn "UFW not installed, skipping firewall configuration"
        log_info "Install UFW with: sudo apt install ufw"
    fi
}

###############################################################################
# Post-Installation
###############################################################################

print_completion_message() {
    echo -e "\n${GREEN}"
    cat << "EOF"
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║           Plumbus Installation Complete! 🎉              ║
    ║         Everyone has one... now you do too!              ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"

    echo -e "${BLUE}Next Steps:${NC}\n"

    echo "1. Start the Plumbus service:"
    echo -e "   ${GREEN}sudo systemctl start $SERVICE_NAME${NC}"
    echo ""

    echo "2. Check service status:"
    echo -e "   ${GREEN}sudo systemctl status $SERVICE_NAME${NC}"
    echo ""

    echo "3. View logs:"
    echo -e "   ${GREEN}sudo journalctl -u $SERVICE_NAME -f${NC}"
    echo ""

    echo "4. Access the web interface:"
    echo -e "   ${GREEN}http://raspberrypi.local:5000${NC}"
    echo -e "   ${GREEN}http://localhost:5000${NC} (from same device)"
    echo ""

    echo -e "${BLUE}Useful Commands:${NC}\n"
    echo "  Stop service:    sudo systemctl stop $SERVICE_NAME"
    echo "  Restart service: sudo systemctl restart $SERVICE_NAME"
    echo "  Disable service: sudo systemctl disable $SERVICE_NAME"
    echo "  View app logs:   tail -f $PROJECT_DIR/logs/plumbus.log"
    echo ""

    echo -e "${YELLOW}Important:${NC}"
    echo "  - The service will auto-start on boot"
    echo "  - Monitor mode will be enabled when service starts"
    echo "  - Data is stored in: $PROJECT_DIR/data/"
    echo "  - Logs are stored in: $PROJECT_DIR/logs/"
    echo ""

    echo -e "${YELLOW}Security Reminder:${NC}"
    echo "  - This device is for PERSONAL security awareness only"
    echo "  - Do NOT use for surveillance of others"
    echo "  - Comply with local privacy laws"
    echo ""
}

###############################################################################
# Main Installation Flow
###############################################################################

main() {
    print_banner

    log_info "Starting installation of $PROJECT_NAME"
    log_info "Installation directory: $PROJECT_DIR"

    # Pre-flight checks
    check_root
    check_raspberry_pi
    check_wifi_interface
    check_monitor_mode_support

    # Installation steps
    step_system_update
    step_install_dependencies
    step_create_venv
    step_install_python_packages
    step_create_directories
    step_configure_monitor_mode
    step_install_service
    step_configure_firewall

    # Complete
    print_completion_message

    # Ask to start now
    echo -n "Do you want to start the Plumbus service now? (y/N): "
    read -r response
    if [[ "$response" =~ ^[Yy]$ ]]; then
        log_info "Starting Plumbus service..."
        sudo systemctl start "$SERVICE_NAME"
        sleep 2
        sudo systemctl status "$SERVICE_NAME" --no-pager
    fi
}

# Run main installation
main "$@"
