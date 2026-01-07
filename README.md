# WiFi Desk Plumbus (WD Plumbus)

```
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║    ██████╗ ██╗     ██╗   ██╗███╗   ███╗██████╗ ██╗   ██╗ ║
    ║    ██╔══██╗██║     ██║   ██║████╗ ████║██╔══██╗██║   ██║ ║
    ║    ██████╔╝██║     ██║   ██║██╔████╔██║██████╔╝██║   ██║ ║
    ║    ██╔═══╝ ██║     ██║   ██║██║╚██╔╝██║██╔══██╗██║   ██║ ║
    ║    ██║     ███████╗╚██████╔╝██║ ╚═╝ ██║██████╔╝╚██████╔╝ ║
    ║    ╚═╝     ╚══════╝ ╚═════╝ ╚═╝     ╚═╝╚═════╝  ╚═════╝  ║
    ║                                                           ║
    ║          Everyone Has One - Now You Can Monitor It       ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝
```

> *"I always wondered how WiFi Plumbuses got made..."* - Interdimensional Cable

## What is a WiFi Desk Plumbus?

A **WiFi Desk Plumbus** is a sophisticated WiFi surveillance detection device built for the Raspberry Pi Zero W/2W. It monitors WiFi networks and probe requests to detect potential physical surveillance by identifying devices that follow you across multiple locations.

Just like a regular Plumbus, everyone should have one - especially if you're security-conscious, travel frequently, or just want to know what wireless devices are lurking around you.

### Key Features

- **Dual-Band Monitoring** - Tracks both 2.4 GHz and 5 GHz WiFi networks
- **SSID Pool Fingerprinting** - Defeats MAC randomization using SSID pool analysis
- **Location Detection** - Automatically identifies location changes based on network environment
- **Following Device Detection** - Alerts when devices appear across multiple locations (Plumbus Stalker Alert!)
- **Real-Time Web Dashboard** - Beautiful Flask-based interface with live WebSocket updates
- **Device Management** - Name, whitelist, and investigate suspicious devices
- **Advanced Analytics** - Historical charts and statistics with Chart.js
- **Privacy-First** - All processing happens locally, no cloud required

## How Does a Plumbus Work?

### The Plumbus Sentinel Process

1. **Fleeb Extraction** (Network Scanning)
   - Continuously scans WiFi networks on both 2.4 GHz and 5 GHz
   - Records SSID, BSSID, RSSI, channel, and encryption type

2. **Dingle Bop Smoothing** (Probe Request Capture)
   - Captures probe requests in WiFi monitor mode using Scapy
   - Extracts SSID pools from devices searching for networks

3. **Schleem Rubbing** (SSID Fingerprinting)
   - Creates unique device signatures based on SSID pool patterns
   - Uses Jaccard similarity coefficient to match devices despite MAC randomization
   - Similarity threshold: 85% (configurable)

4. **Grumbo Shaving** (Location Detection)
   - Builds location fingerprints from visible BSSIDs
   - Compares current environment to historical locations
   - Automatically names and tracks locations

5. **Fleeb Juice Repurposing** (Following Detection)
   - Correlates device appearances across multiple locations
   - Calculates movement correlation scores
   - Triggers alerts when devices follow you (≥3 locations)

6. **Final Plumbus** (Dashboard & Alerts)
   - Real-time web dashboard with WebSocket updates
   - Interactive charts showing device activity
   - Alert system for suspicious devices

## Hardware Requirements

### Required Components

| Component | Specification | Qty | Cost (CHF) |
|-----------|--------------|-----|------------|
| Raspberry Pi Zero W/2W | WiFi 2.4+5GHz, 512MB RAM | 1 | 25 |
| microSD Card | 32GB Class 10 or better | 1 | 10 |
| USB-C Cable | 1.5m USB-C cable for power | 1 | 5 |
| Power Supply | 5V 2.5A USB adapter | 1 | 10 |
| Case (optional) | Official RPi Zero case or 3D printed | 1 | 5 |
| **TOTAL** | | | **CHF 50-55** |

### Compatibility Notes

- **Tested on**: Raspberry Pi Zero W and Zero 2 W
- **WiFi Chip**: CYW43455 (dual-band support)
- **Monitor Mode**: Firmware 7.45.241 or later (included in recent Raspberry Pi OS)

## Installation

### Prerequisites

1. **Raspberry Pi OS Lite** (Debian Bookworm or newer)
2. **SSH Access** to your Raspberry Pi
3. **Internet Connection** for initial setup
4. **Root/sudo privileges**

### Automated Installation (Recommended)

```bash
# 1. Clone the repository
git clone https://github.com/elm1nst3r/DeskPlumbus.git
cd DeskPlumbus

# 2. Run the automated installer
chmod +x install.sh
./install.sh

# 3. Access the web interface
# From same device: http://localhost:5000
# From other devices: http://raspberrypi.local:5000
```

The installer will:
- Update system packages
- Install Python dependencies
- Create virtual environment
- Initialize SQLite database
- Configure WiFi monitor mode
- Install and start systemd service
- Configure firewall

**Installation time**: ~15 minutes

### Manual Installation

<details>
<summary>Click to expand manual installation steps</summary>

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install system dependencies
sudo apt install -y python3-pip python3-venv iw wireless-tools tcpdump

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python packages
pip install -r requirements.txt

# Enable monitor mode
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up

# Initialize database
python3 -c "from app.database import init_db; init_db()"

# Install systemd service
sudo cp plumbus.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable plumbus.service
sudo systemctl start plumbus.service

# Configure firewall
sudo ufw allow 5000/tcp
sudo ufw enable
```

</details>

## Usage

### Accessing the Dashboard

Once installed and running, access the web interface:

- **Local**: http://localhost:5000
- **Network**: http://raspberrypi.local:5000
- **IP**: http://[PI_IP_ADDRESS]:5000

### Managing the Service

```bash
# Check status
sudo systemctl status plumbus

# Start service
sudo systemctl start plumbus

# Stop service
sudo systemctl stop plumbus

# Restart service
sudo systemctl restart plumbus

# View logs
sudo journalctl -u plumbus -f

# View application logs
tail -f logs/plumbus.log
```

### Configuration

Edit `config.py` to customize settings:

```python
# WiFi Settings
WIFI_INTERFACE = 'wlan0'
SCAN_INTERVAL = 5  # seconds

# Fingerprinting
SIMILARITY_THRESHOLD = 0.85  # 85% match required

# Alerts
ALERT_LOCATION_COUNT = 3  # Alert after device seen at 3 locations
ALERT_TIME_WINDOW = 1800  # 30 minutes

# Data Retention
DATA_RETENTION_DAYS = 90  # Auto-delete old data
```

## Dashboard Features

### Main Dashboard
- **Current Location**: Shows detected location with confidence score
- **Devices Around You**: List of nearby devices categorized as Known/Neutral/Suspicious
- **Quick Statistics**: Total devices, known devices, alerts, networks
- **System Status**: WiFi interface health, monitoring status, database size

### Network Scanner
- **Dual-Band Display**: Separate views for 2.4 GHz and 5 GHz
- **Channel Map**: Visual spectrum representation
- **Signal Strength**: Color-coded RSSI values
- **Encryption Types**: WPA2, WPA3, WEP, Open

### Device Management
- **Custom Naming**: Assign friendly names to device fingerprints
- **Whitelisting**: Mark trusted devices
- **Investigation Notes**: Add timestamped notes
- **Timeline View**: Interactive device location history
- **SSID Pool**: Complete list of probed networks

### Analytics & Statistics
- **Device Activity Charts**: Activity over time (Chart.js)
- **Location Distribution**: Time spent at each location
- **Band Analysis**: 2.4 GHz vs 5 GHz usage
- **Heatmaps**: Busiest times and days
- **Alert History**: Complete alert log

## Security & Privacy

### Legal Notice

⚠️ **IMPORTANT**: WiFi monitoring may be subject to local privacy laws. This device is for **PERSONAL security awareness ONLY**. Do NOT use for surveillance of others.

- Complies with Swiss Federal Act on Data Protection (FADP) for personal use
- MAC addresses may be considered personal data under GDPR/FADP
- Only use in your own home or with explicit consent
- Consult legal counsel if using for commercial purposes

### Privacy Measures

- **Local Processing**: All data stays on your Raspberry Pi
- **No Cloud**: Zero internet connections required after installation
- **Auto-Deletion**: Configurable data retention (default 90 days)
- **Minimal Data**: Only captures metadata (MAC, SSID, RSSI)
- **Optional Encryption**: SQLite database can be encrypted
- **Password Protection**: Optional Flask-Login authentication

### Security Best Practices

```bash
# Change default password
passwd

# Disable password SSH (use keys only)
sudo nano /etc/ssh/sshd_config
# Set: PasswordAuthentication no

# Install fail2ban
sudo apt install fail2ban

# Configure firewall
sudo ufw allow 5000/tcp
sudo ufw enable

# Keep system updated
sudo apt update && sudo apt upgrade
```

## Troubleshooting

### Monitor Mode Issues

```bash
# Check WiFi firmware version
sudo iw phy | grep -i firmware

# Should be 7.45.241 or later
# If not, update Raspberry Pi OS:
sudo apt update && sudo apt full-upgrade
```

### Service Won't Start

```bash
# Check logs
sudo journalctl -u plumbus -n 50

# Common issues:
# - WiFi interface busy: Disable NetworkManager on wlan0
# - Permissions: Ensure pi user has sudo rights
# - Dependencies: Reinstall with pip install -r requirements.txt
```

### No Devices Detected

```bash
# Verify monitor mode is active
iwconfig wlan0
# Should show "Mode:Monitor"

# Check for probe requests manually
sudo tcpdump -i wlan0 -e -s 256 type mgt subtype probe-req

# Verify Scapy can capture
sudo python3 -c "from scapy.all import *; sniff(iface='wlan0', count=5)"
```

### Web Interface Not Accessible

```bash
# Check Flask is running
sudo systemctl status plumbus

# Check port 5000 is listening
sudo netstat -tlnp | grep 5000

# Check firewall
sudo ufw status

# Try local access first
curl http://localhost:5000
```

## Architecture

### Technology Stack

- **Python 3.11+**: Main programming language
- **Scapy**: WiFi packet capture in monitor mode
- **Flask**: Web framework
- **Flask-SocketIO**: Real-time WebSocket updates
- **SQLite**: Embedded database
- **Chart.js**: Interactive visualizations
- **systemd**: Service management

### Project Structure

```
DeskPlumbus/
├── app/
│   ├── __init__.py          # Flask app initialization
│   ├── monitor.py           # WiFi packet capture
│   ├── fingerprint.py       # SSID pool matching
│   ├── location.py          # Location detection
│   ├── database.py          # SQLite operations
│   ├── api.py               # REST API endpoints
│   └── websocket.py         # WebSocket handlers
├── web/
│   ├── static/
│   │   ├── css/            # Stylesheets
│   │   ├── js/             # JavaScript
│   │   └── images/         # Icons and logos
│   └── templates/
│       └── index.html      # Main dashboard
├── data/
│   └── tracker.db          # SQLite database
├── logs/
│   └── plumbus.log         # Application logs
├── tests/                  # Unit tests
├── config.py               # Configuration
├── run.py                  # Application entry point
├── install.sh              # Automated installer
└── plumbus.service         # Systemd service
```

## Development

### Running in Development Mode

```bash
# Activate virtual environment
source venv/bin/activate

# Run with auto-reload
export FLASK_ENV=development
sudo -E python3 run.py
```

### Running Tests

```bash
# Install test dependencies
pip install pytest pytest-cov

# Run tests
pytest tests/

# With coverage
pytest --cov=app tests/
```

### Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Roadmap

### Phase 0: Project Foundation ✅
- [x] Project structure and documentation
- [x] Configuration management
- [x] Installation scripts
- [x] Database schema

### Phase 1: Core WiFi Monitoring ✅
- [x] WiFi monitor mode management
- [x] Network scanner (2.4 GHz + 5 GHz)
- [x] Scapy packet capture
- [x] Basic Flask web dashboard
- [x] SQLite database operations

### Phase 2: SSID Fingerprinting ✅
- [x] SSID pool extraction from probe requests
- [x] Jaccard similarity matching
- [x] MAC randomization defeat
- [x] Device fingerprint database
- [x] Fingerprint statistics API

### Phase 3: Location Detection ✅
- [x] BSSID pool location fingerprinting
- [x] Automatic location detection
- [x] Location tracking & management
- [x] Location statistics & analytics

### Phase 4: Following Device Detection ✅
- [x] Cross-location device tracking
- [x] Movement correlation scoring
- [x] Alert system for suspicious devices
- [x] Whitelist management
- [x] Device status management API

### Phase 5: Real-time Analytics ✅
- [x] Flask-SocketIO WebSocket integration
- [x] Real-time dashboard updates (2s interval)
- [x] Chart.js device activity timeline
- [x] Toast notifications for alerts
- [x] Live connection status indicator
- [x] Background broadcast task

### Phase 6: Production Polish (In Progress)
- [ ] Enhanced error handling & logging
- [ ] Authentication/password protection
- [ ] Database optimization & indexing
- [ ] Production deployment scripts
- [ ] Performance optimization
- [ ] Comprehensive testing

## FAQ

**Q: Will this detect ALL devices following me?**
A: No device can guarantee 100% detection. The Plumbus works best for devices that actively probe for WiFi networks. Devices that only listen passively won't be detected.

**Q: What about devices that don't broadcast probe requests?**
A: Modern iOS and Android devices use MAC randomization and probe less frequently. The SSID pool fingerprinting technique helps identify these devices despite randomization.

**Q: Can I use this on Raspberry Pi 4 or 5?**
A: Yes! The code is optimized for Pi Zero W but runs even better on more powerful Pi models.

**Q: Does this work without internet?**
A: Yes! After installation, the Plumbus operates completely offline.

**Q: How much power does it consume?**
A: The Pi Zero W draws 150-200mA (~1W), so it can run 24/7 for a few dollars per year.

**Q: Can I power it from a battery?**
A: Yes! Use a USB power bank (10,000mAh will run it for 2-3 days).

## Credits

- **Author**: Roy (elm1nst3r)
- **Inspired by**: Daniel's WiFi Tracker BRD - Cy-fense
- **Plumbus**: Justin Roiland & Dan Harmon (Rick and Morty)
- **Platform**: Raspberry Pi Foundation

## License

This project is for educational and personal security purposes only. Use responsibly and in compliance with local laws.

## Disclaimer

The WiFi Desk Plumbus is a security research and personal awareness tool. The authors are not responsible for any misuse or legal consequences. Always respect privacy laws and obtain necessary permissions before deploying surveillance detection equipment.

**Remember**: A Plumbus is a tool for personal protection, not for invading others' privacy!

---

*Made with ❤️ and a healthy dose of interdimensional cable*

**"I always wondered how Plumbuses got made..."** - Now you know!
