"""
WiFi Desk Plumbus - WiFi Management Module

This module handles WiFi interface management with intelligent mode switching:
- Automatic USB WiFi adapter detection
- Dual-interface mode: wlan0 (monitor) + wlan1 (management)
- Single-interface mode: wlan0 time-sliced (monitor + brief managed periods)
- Network scanning and connection management
- AP mode for direct access
- Network profile management

Architecture:
- If USB WiFi detected (wlan1): Use for management while wlan0 does surveillance
- If no USB WiFi: Time-slice wlan0 (90% monitor mode, 10% managed mode)
"""

import logging
import subprocess
import time
import json
import os
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum

import config

logger = logging.getLogger(__name__)


class WifiMode(Enum):
    """WiFi interface modes."""
    MONITOR = "monitor"
    MANAGED = "managed"
    AP = "ap"


class ManagementStrategy(Enum):
    """Management interface strategy."""
    DUAL_INTERFACE = "dual_interface"  # USB WiFi available
    TIME_SLICED = "time_sliced"  # Single interface, time-slicing
    AP_MODE = "ap_mode"  # Hotspot mode


@dataclass
class WifiInterface:
    """WiFi interface information."""
    name: str  # e.g., wlan0, wlan1
    mac_address: str
    driver: str
    is_usb: bool
    current_mode: Optional[WifiMode] = None
    connected_ssid: Optional[str] = None
    ip_address: Optional[str] = None
    signal_strength: Optional[int] = None


@dataclass
class WifiNetwork:
    """Scanned WiFi network."""
    ssid: str
    bssid: str
    frequency: int
    signal_strength: int  # dBm
    encryption: str  # WPA2, WPA3, Open, etc.
    channel: int


@dataclass
class NetworkProfile:
    """Saved network profile."""
    ssid: str
    password: str
    priority: int = 0  # Higher = prefer this network
    auto_connect: bool = True


class WiFiManager:
    """
    Manages WiFi interfaces with intelligent mode switching.

    Features:
    - Automatic USB WiFi detection
    - Dual-interface operation (surveillance + management)
    - Time-slicing for single interface
    - Network scanning and connection
    - AP mode support
    - Profile management
    """

    def __init__(self):
        self.surveillance_interface: Optional[WifiInterface] = None
        self.management_interface: Optional[WifiInterface] = None
        self.strategy: ManagementStrategy = ManagementStrategy.TIME_SLICED

        # Time-slicing parameters
        self.monitor_duration = 270  # 4.5 minutes (90%)
        self.managed_duration = 30   # 30 seconds (10%)
        self.last_switch_time = time.time()

        # Network profiles
        self.profiles_file = config.DATA_DIR / "network_profiles.json"
        self.profiles: List[NetworkProfile] = []

        # AP configuration
        self.ap_ssid = "Plumbus-WiFi"
        self.ap_password = "plumbus123"
        self.ap_ip = "192.168.4.1"

        logger.info("WiFi Manager initialized")

    def initialize(self):
        """Initialize WiFi manager and detect interfaces."""
        logger.info("Detecting WiFi interfaces...")

        # Detect all WiFi interfaces
        interfaces = self._detect_interfaces()

        if not interfaces:
            logger.error("No WiFi interfaces detected!")
            return False

        logger.info(f"Found {len(interfaces)} WiFi interface(s)")

        # Determine strategy based on available interfaces
        if len(interfaces) >= 2:
            # Dual interface mode: Check user preference or use defaults
            surveillance_pref = config.WIFI_SURVEILLANCE_INTERFACE if hasattr(config, 'WIFI_SURVEILLANCE_INTERFACE') else None
            management_pref = config.WIFI_MANAGEMENT_INTERFACE if hasattr(config, 'WIFI_MANAGEMENT_INTERFACE') else None

            # Apply user preferences if set
            if surveillance_pref and management_pref:
                # Find interfaces by name
                surv = next((i for i in interfaces if i.name == surveillance_pref), None)
                mgmt = next((i for i in interfaces if i.name == management_pref), None)

                if surv and mgmt and surv.name != mgmt.name:
                    self.surveillance_interface = surv
                    self.management_interface = mgmt
                    logger.info(f"✅ Using user-configured interface assignment")
                else:
                    logger.warning("Invalid interface configuration, using defaults")
                    self.surveillance_interface = interfaces[0]
                    self.management_interface = interfaces[1]
            else:
                # Default: built-in for surveillance, USB for management
                self.surveillance_interface = interfaces[0]  # wlan0 (built-in)
                self.management_interface = interfaces[1]    # wlan1 (USB)

            self.strategy = ManagementStrategy.DUAL_INTERFACE
            logger.info("✅ Strategy: DUAL INTERFACE (optimal)")
            logger.info(f"  Surveillance: {self.surveillance_interface.name} ({self.surveillance_interface.driver}) (always monitor mode)")
            logger.info(f"  Management: {self.management_interface.name} ({self.management_interface.driver}) (always managed mode)")
        else:
            # Single interface mode: Time-slicing
            self.surveillance_interface = interfaces[0]
            self.management_interface = interfaces[0]  # Same interface
            self.strategy = ManagementStrategy.TIME_SLICED
            logger.info("⚠️  Strategy: TIME SLICED (single interface)")
            logger.info(f"  Interface: {self.surveillance_interface.name}")
            logger.info(f"  Monitor: {self.monitor_duration}s, Managed: {self.managed_duration}s")

        # Load saved network profiles
        self._load_profiles()

        # Initialize interfaces
        self._setup_interfaces()

        return True

    def _detect_interfaces(self) -> List[WifiInterface]:
        """Detect all WiFi interfaces on the system."""
        interfaces = []

        try:
            # Use iw to list wireless interfaces
            result = subprocess.run(
                ['iw', 'dev'],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode != 0:
                logger.error("Failed to detect WiFi interfaces")
                return interfaces

            # Parse iw output
            current_interface = None
            for line in result.stdout.split('\n'):
                line = line.strip()

                if line.startswith('Interface'):
                    # Interface wlan0
                    name = line.split()[1]
                    current_interface = {'name': name}

                elif line.startswith('addr') and current_interface:
                    # addr aa:bb:cc:dd:ee:ff
                    mac = line.split()[1]
                    current_interface['mac_address'] = mac

                elif line.startswith('type') and current_interface:
                    # type managed
                    mode = line.split()[1]
                    current_interface['current_mode'] = WifiMode(mode) if mode in ['monitor', 'managed'] else None

                    # Determine if USB by checking interface name and driver
                    is_usb = current_interface['name'] != 'wlan0'
                    driver = self._get_interface_driver(current_interface['name'])

                    interface = WifiInterface(
                        name=current_interface['name'],
                        mac_address=current_interface['mac_address'],
                        driver=driver,
                        is_usb=is_usb,
                        current_mode=current_interface.get('current_mode')
                    )

                    interfaces.append(interface)
                    current_interface = None

            # Sort by name (wlan0 first, then wlan1, etc.)
            interfaces.sort(key=lambda x: x.name)

        except Exception as e:
            logger.error(f"Error detecting interfaces: {e}", exc_info=True)

        return interfaces

    def _get_interface_driver(self, interface_name: str) -> str:
        """Get driver name for interface."""
        try:
            driver_path = f"/sys/class/net/{interface_name}/device/driver"
            if os.path.exists(driver_path):
                driver = os.path.basename(os.readlink(driver_path))
                return driver
        except Exception:
            pass
        return "unknown"

    def _setup_interfaces(self):
        """Set up interfaces based on strategy."""
        if self.strategy == ManagementStrategy.DUAL_INTERFACE:
            # Set surveillance interface to monitor mode
            self._set_mode(self.surveillance_interface.name, WifiMode.MONITOR)

            # Set management interface to managed mode
            self._set_mode(self.management_interface.name, WifiMode.MANAGED)

            # Try to connect to saved networks
            self._auto_connect()

        elif self.strategy == ManagementStrategy.TIME_SLICED:
            # Start in monitor mode
            self._set_mode(self.surveillance_interface.name, WifiMode.MONITOR)
            self.last_switch_time = time.time()

    def _set_mode(self, interface: str, mode: WifiMode) -> bool:
        """Set WiFi interface mode."""
        try:
            logger.info(f"Setting {interface} to {mode.value} mode")

            # Bring interface down
            subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'down'], check=True)

            # Set mode
            subprocess.run(['sudo', 'iw', interface, 'set', 'type', mode.value], check=True)

            # Bring interface up
            subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'up'], check=True)

            logger.info(f"✅ {interface} now in {mode.value} mode")
            return True

        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to set {interface} to {mode.value}: {e}")
            return False

    def manage_time_slicing(self):
        """
        Manage time-slicing for single interface mode.
        Call this periodically from main loop.
        """
        if self.strategy != ManagementStrategy.TIME_SLICED:
            return  # Not needed in dual interface mode

        current_time = time.time()
        elapsed = current_time - self.last_switch_time

        current_mode = self.surveillance_interface.current_mode

        # Check if we need to switch modes
        if current_mode == WifiMode.MONITOR and elapsed >= self.monitor_duration:
            # Switch to managed mode for brief management access
            logger.info("⏰ Time-slice: Switching to MANAGED mode (30s)")
            self._set_mode(self.surveillance_interface.name, WifiMode.MANAGED)
            self.surveillance_interface.current_mode = WifiMode.MANAGED
            self.last_switch_time = current_time

        elif current_mode == WifiMode.MANAGED and elapsed >= self.managed_duration:
            # Switch back to monitor mode
            logger.info("⏰ Time-slice: Switching back to MONITOR mode (4.5min)")
            self._set_mode(self.surveillance_interface.name, WifiMode.MONITOR)
            self.surveillance_interface.current_mode = WifiMode.MONITOR
            self.last_switch_time = current_time

    def scan_networks(self) -> List[WifiNetwork]:
        """Scan for available WiFi networks."""
        networks = []

        # Use management interface
        interface = self.management_interface.name

        # If time-sliced, temporarily switch to managed mode
        temp_switch = False
        if self.strategy == ManagementStrategy.TIME_SLICED:
            if self.surveillance_interface.current_mode == WifiMode.MONITOR:
                logger.info("Temporarily switching to managed mode for scan")
                self._set_mode(interface, WifiMode.MANAGED)
                temp_switch = True
                time.sleep(2)  # Wait for interface to stabilize

        try:
            # Use iw to scan
            result = subprocess.run(
                ['sudo', 'iw', interface, 'scan'],
                capture_output=True,
                text=True,
                timeout=15
            )

            if result.returncode != 0:
                logger.error(f"Scan failed: {result.stderr}")
                return networks

            # Parse scan results
            current_network = {}
            for line in result.stdout.split('\n'):
                line = line.strip()

                if line.startswith('BSS '):
                    # Save previous network
                    if current_network.get('ssid'):
                        networks.append(WifiNetwork(**current_network))

                    # Start new network
                    bssid = line.split()[1].rstrip('(on')
                    current_network = {'bssid': bssid}

                elif line.startswith('freq:'):
                    current_network['frequency'] = int(line.split()[1])
                    current_network['channel'] = self._freq_to_channel(current_network['frequency'])

                elif line.startswith('signal:'):
                    # signal: -45.00 dBm
                    signal = float(line.split()[1])
                    current_network['signal_strength'] = int(signal)

                elif line.startswith('SSID:'):
                    ssid = line.split('SSID:', 1)[1].strip()
                    current_network['ssid'] = ssid if ssid else '(hidden)'

                elif 'WPA' in line or 'RSN' in line:
                    if 'WPA3' in line:
                        current_network['encryption'] = 'WPA3'
                    elif 'WPA2' in line:
                        current_network['encryption'] = 'WPA2'
                    elif 'WPA' in line:
                        current_network['encryption'] = 'WPA'
                elif 'Open' in line and 'encryption' not in current_network:
                    current_network['encryption'] = 'Open'

            # Add last network
            if current_network.get('ssid'):
                # Set default encryption if not detected
                if 'encryption' not in current_network:
                    current_network['encryption'] = 'WPA2'
                networks.append(WifiNetwork(**current_network))

            # Sort by signal strength
            networks.sort(key=lambda x: x.signal_strength, reverse=True)

            logger.info(f"Found {len(networks)} networks")

        except Exception as e:
            logger.error(f"Error scanning networks: {e}", exc_info=True)

        finally:
            # Switch back to monitor mode if we temporarily switched
            if temp_switch:
                logger.info("Switching back to monitor mode")
                self._set_mode(interface, WifiMode.MONITOR)

        return networks

    def connect_to_network(self, ssid: str, password: str) -> Tuple[bool, str]:
        """Connect to a WiFi network."""
        interface = self.management_interface.name

        logger.info(f"Connecting to network: {ssid}")

        try:
            # Create wpa_supplicant config
            wpa_config = f"""
ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev
update_config=1
country=US

network={{
    ssid="{ssid}"
    psk="{password}"
    key_mgmt=WPA-PSK
}}
"""

            # Write config to temp file
            config_file = f"/tmp/wpa_supplicant_{interface}.conf"
            with open(config_file, 'w') as f:
                f.write(wpa_config)

            # Stop existing wpa_supplicant
            subprocess.run(['sudo', 'killall', 'wpa_supplicant'], stderr=subprocess.DEVNULL)
            time.sleep(1)

            # Start wpa_supplicant
            subprocess.Popen(
                ['sudo', 'wpa_supplicant', '-B', '-i', interface, '-c', config_file],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

            time.sleep(3)

            # Request IP via DHCP
            subprocess.run(['sudo', 'dhclient', interface], timeout=10)

            # Check if connected
            time.sleep(2)
            ip = self._get_interface_ip(interface)

            if ip:
                logger.info(f"✅ Connected to {ssid} - IP: {ip}")
                self.management_interface.connected_ssid = ssid
                self.management_interface.ip_address = ip

                # Save to profiles
                self.save_profile(ssid, password)

                return True, f"Connected successfully! IP: {ip}"
            else:
                logger.error(f"Failed to get IP address")
                return False, "Connected but failed to get IP address"

        except Exception as e:
            logger.error(f"Connection error: {e}", exc_info=True)
            return False, f"Connection failed: {str(e)}"

    def _get_interface_ip(self, interface: str) -> Optional[str]:
        """Get IP address of interface."""
        try:
            result = subprocess.run(
                ['ip', 'addr', 'show', interface],
                capture_output=True,
                text=True
            )

            for line in result.stdout.split('\n'):
                if 'inet ' in line:
                    ip = line.strip().split()[1].split('/')[0]
                    return ip
        except Exception:
            pass
        return None

    def _freq_to_channel(self, freq: int) -> int:
        """Convert frequency to channel number."""
        if 2412 <= freq <= 2484:
            return (freq - 2412) // 5 + 1
        elif 5170 <= freq <= 5825:
            return (freq - 5170) // 5 + 34
        return 0

    def save_profile(self, ssid: str, password: str, priority: int = 0):
        """Save network profile."""
        # Check if profile exists
        for profile in self.profiles:
            if profile.ssid == ssid:
                profile.password = password
                profile.priority = priority
                self._save_profiles()
                return

        # Add new profile
        profile = NetworkProfile(ssid=ssid, password=password, priority=priority)
        self.profiles.append(profile)
        self._save_profiles()
        logger.info(f"Saved network profile: {ssid}")

    def _load_profiles(self):
        """Load saved network profiles."""
        try:
            if self.profiles_file.exists():
                with open(self.profiles_file, 'r') as f:
                    data = json.load(f)
                    self.profiles = [NetworkProfile(**p) for p in data]
                logger.info(f"Loaded {len(self.profiles)} network profiles")
        except Exception as e:
            logger.error(f"Error loading profiles: {e}")
            self.profiles = []

    def _save_profiles(self):
        """Save network profiles to disk."""
        try:
            with open(self.profiles_file, 'w') as f:
                data = [asdict(p) for p in self.profiles]
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving profiles: {e}")

    def _auto_connect(self):
        """Try to auto-connect to saved networks."""
        if not self.profiles:
            return

        # Sort by priority
        sorted_profiles = sorted(self.profiles, key=lambda p: p.priority, reverse=True)

        for profile in sorted_profiles:
            if profile.auto_connect:
                logger.info(f"Attempting auto-connect to {profile.ssid}")
                success, msg = self.connect_to_network(profile.ssid, profile.password)
                if success:
                    return

    def get_status(self) -> Dict:
        """Get current WiFi manager status."""
        # Helper to convert interface to dict with enum values serialized
        def interface_to_dict(iface):
            if not iface:
                return None
            data = asdict(iface)
            # Convert WifiMode enum to string
            if data.get('current_mode'):
                data['current_mode'] = data['current_mode'].value
            return data

        return {
            'strategy': self.strategy.value,
            'surveillance_interface': interface_to_dict(self.surveillance_interface),
            'management_interface': interface_to_dict(self.management_interface),
            'time_slicing': {
                'monitor_duration': self.monitor_duration,
                'managed_duration': self.managed_duration,
                'time_since_last_switch': time.time() - self.last_switch_time
            } if self.strategy == ManagementStrategy.TIME_SLICED else None,
            'profiles_count': len(self.profiles),
            'available_interfaces': self.get_available_interfaces()
        }

    def get_available_interfaces(self) -> List[Dict]:
        """Get list of all available WiFi interfaces."""
        interfaces = self._detect_interfaces()
        return [
            {
                'name': i.name,
                'mac_address': i.mac_address,
                'driver': i.driver,
                'is_usb': i.is_usb,
                'current_mode': i.current_mode.value if i.current_mode else None
            }
            for i in interfaces
        ]

    def swap_interfaces(self) -> Tuple[bool, str]:
        """Swap surveillance and management interface assignments."""
        if self.strategy != ManagementStrategy.DUAL_INTERFACE:
            return False, "Interface swapping only available in dual interface mode"

        logger.info("Swapping interface assignments...")

        # Swap the interfaces
        self.surveillance_interface, self.management_interface = \
            self.management_interface, self.surveillance_interface

        # Reinitialize with new assignments
        self._setup_interfaces()

        logger.info(f"✅ Interfaces swapped")
        logger.info(f"  Surveillance: {self.surveillance_interface.name}")
        logger.info(f"  Management: {self.management_interface.name}")

        return True, f"Surveillance: {self.surveillance_interface.name}, Management: {self.management_interface.name}"

    def set_interface_assignment(self, surveillance_name: str, management_name: str) -> Tuple[bool, str]:
        """Manually assign interfaces to roles."""
        if self.strategy != ManagementStrategy.DUAL_INTERFACE:
            return False, "Manual assignment only available in dual interface mode"

        interfaces = self._detect_interfaces()

        # Find interfaces by name
        surv = next((i for i in interfaces if i.name == surveillance_name), None)
        mgmt = next((i for i in interfaces if i.name == management_name), None)

        if not surv:
            return False, f"Interface {surveillance_name} not found"
        if not mgmt:
            return False, f"Interface {management_name} not found"
        if surv.name == mgmt.name:
            return False, "Surveillance and management must use different interfaces"

        logger.info(f"Setting manual interface assignment:")
        logger.info(f"  Surveillance: {surveillance_name}")
        logger.info(f"  Management: {management_name}")

        self.surveillance_interface = surv
        self.management_interface = mgmt

        # Reinitialize with new assignments
        self._setup_interfaces()

        return True, f"Assigned {surveillance_name} to surveillance, {management_name} to management"


# Global instance
_wifi_manager: Optional[WiFiManager] = None


def get_wifi_manager() -> WiFiManager:
    """Get the global WiFi manager instance."""
    global _wifi_manager
    if _wifi_manager is None:
        _wifi_manager = WiFiManager()
    return _wifi_manager


def initialize_wifi_manager():
    """Initialize the WiFi manager."""
    manager = get_wifi_manager()
    return manager.initialize()
