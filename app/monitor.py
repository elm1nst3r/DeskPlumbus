"""
WiFi Desk Plumbus - WiFi Monitor Module

This module handles WiFi packet capture in monitor mode using Scapy.

Implements:
- Monitor mode enable/disable
- Probe request capture
- Beacon frame capture (network scanning)
- Dual-band monitoring (2.4 + 5 GHz)
- Packet queue for processing
"""

import logging
import subprocess
import threading
import queue
import time
from datetime import datetime
from typing import Optional, Dict, Any, Callable

try:
    from scapy.all import (
        sniff, Dot11, Dot11Beacon, Dot11ProbeReq, Dot11Elt,
        RadioTap, Packet
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logging.warning("Scapy not available - WiFi monitoring will not work")

import config

logger = logging.getLogger(__name__)


class WiFiMonitor:
    """WiFi monitor for capturing probe requests and beacon frames."""

    def __init__(self, interface: str = None):
        """
        Initialize WiFi monitor.

        Args:
            interface: WiFi interface name (default: from config)
        """
        self.interface = interface or config.WIFI_INTERFACE
        self.running = False
        self.monitor_mode_enabled = False
        self.packet_queue = queue.Queue(maxsize=config.CAPTURE_QUEUE_SIZE)
        self.capture_thread = None

        # Statistics
        self.packets_captured = 0
        self.probe_requests = 0
        self.beacons = 0

        # Callbacks for packet processing
        self.probe_callback: Optional[Callable] = None
        self.beacon_callback: Optional[Callable] = None

        logger.info(f"WiFi Monitor initialized for interface: {self.interface}")

    def enable_monitor_mode(self) -> bool:
        """
        Enable monitor mode on WiFi interface.

        Returns:
            bool: True if successful, False otherwise
        """
        if not SCAPY_AVAILABLE:
            logger.error("Scapy not available - cannot enable monitor mode")
            return False

        try:
            logger.info(f"Enabling monitor mode on {self.interface}...")

            # Bring interface down
            subprocess.run(
                ['sudo', 'ip', 'link', 'set', self.interface, 'down'],
                check=True,
                capture_output=True
            )

            # Set to monitor mode
            subprocess.run(
                ['sudo', 'iw', 'dev', self.interface, 'set', 'type', 'monitor'],
                check=True,
                capture_output=True
            )

            # Bring interface up
            subprocess.run(
                ['sudo', 'ip', 'link', 'set', self.interface, 'up'],
                check=True,
                capture_output=True
            )

            self.monitor_mode_enabled = True
            logger.info(f"Monitor mode enabled on {self.interface}")
            return True

        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to enable monitor mode: {e.stderr.decode()}")
            return False
        except Exception as e:
            logger.error(f"Error enabling monitor mode: {e}")
            return False

    def disable_monitor_mode(self) -> bool:
        """
        Disable monitor mode and return to managed mode.

        Returns:
            bool: True if successful, False otherwise
        """
        if not self.monitor_mode_enabled:
            return True

        try:
            logger.info(f"Disabling monitor mode on {self.interface}...")

            # Bring interface down
            subprocess.run(
                ['sudo', 'ip', 'link', 'set', self.interface, 'down'],
                check=True,
                capture_output=True
            )

            # Set to managed mode
            subprocess.run(
                ['sudo', 'iw', 'dev', self.interface, 'set', 'type', 'managed'],
                check=True,
                capture_output=True
            )

            # Bring interface up
            subprocess.run(
                ['sudo', 'ip', 'link', 'set', self.interface, 'up'],
                check=True,
                capture_output=True
            )

            self.monitor_mode_enabled = False
            logger.info(f"Monitor mode disabled on {self.interface}")
            return True

        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to disable monitor mode: {e.stderr.decode()}")
            return False
        except Exception as e:
            logger.error(f"Error disabling monitor mode: {e}")
            return False

    def _packet_handler(self, packet: Packet):
        """
        Handle captured packets.

        Args:
            packet: Scapy packet object
        """
        try:
            self.packets_captured += 1

            # Check if it's a probe request
            if packet.haslayer(Dot11ProbeReq):
                self._handle_probe_request(packet)

            # Check if it's a beacon frame
            elif packet.haslayer(Dot11Beacon):
                self._handle_beacon(packet)

        except Exception as e:
            logger.error(f"Error handling packet: {e}", exc_info=True)

    def _handle_probe_request(self, packet: Packet):
        """
        Handle probe request packets.

        Args:
            packet: Scapy packet with Dot11ProbeReq layer
        """
        try:
            self.probe_requests += 1

            # Extract MAC address
            mac_address = packet[Dot11].addr2

            # Extract SSID if present
            ssid = ""
            if packet.haslayer(Dot11Elt):
                ssid = packet[Dot11Elt].info.decode('utf-8', errors='ignore')

            # Determine frequency band from RadioTap
            frequency_band = "2.4GHz"  # Default
            if packet.haslayer(RadioTap):
                # RadioTap may contain frequency information
                # This is a simplified approach
                pass

            # Create probe data
            probe_data = {
                'mac_address': mac_address,
                'ssid': ssid,
                'frequency_band': frequency_band,
                'timestamp': int(datetime.now().timestamp())
            }

            # Call callback if registered
            if self.probe_callback:
                self.probe_callback(probe_data)

            if config.VERBOSE_LOGGING:
                logger.debug(f"Probe request: MAC={mac_address}, SSID={ssid}")

        except Exception as e:
            logger.error(f"Error handling probe request: {e}", exc_info=True)

    def _handle_beacon(self, packet: Packet):
        """
        Handle beacon frame packets (network announcements).

        Args:
            packet: Scapy packet with Dot11Beacon layer
        """
        try:
            self.beacons += 1

            # Extract BSSID (AP MAC address)
            bssid = packet[Dot11].addr2

            # Extract SSID
            ssid = ""
            channel = 0
            if packet.haslayer(Dot11Elt):
                # SSID is in the first Dot11Elt layer
                ssid = packet[Dot11Elt].info.decode('utf-8', errors='ignore')

                # Channel info might be in DS Parameter Set
                elt = packet[Dot11Elt]
                while elt:
                    if elt.ID == 3:  # DS Parameter Set
                        channel = ord(elt.info)
                        break
                    elt = elt.payload.getlayer(Dot11Elt)

            # Determine frequency band from channel
            if 1 <= channel <= 14:
                frequency_band = "2.4GHz"
            elif 36 <= channel <= 165:
                frequency_band = "5GHz"
            else:
                frequency_band = "Unknown"

            # Extract signal strength (RSSI)
            rssi = -100  # Default weak signal
            if packet.haslayer(RadioTap) and hasattr(packet[RadioTap], 'dBm_AntSignal'):
                rssi = packet[RadioTap].dBm_AntSignal

            # Determine encryption type
            encryption = "Open"
            if packet.haslayer(Dot11Beacon):
                cap = packet[Dot11Beacon].cap
                if cap & 0x10:  # Privacy bit
                    encryption = "WPA/WPA2"  # Simplified

            # Create network data
            network_data = {
                'ssid': ssid,
                'bssid': bssid,
                'channel': channel,
                'frequency_band': frequency_band,
                'rssi': rssi,
                'encryption': encryption,
                'timestamp': int(datetime.now().timestamp())
            }

            # Call callback if registered
            if self.beacon_callback:
                self.beacon_callback(network_data)

            if config.VERBOSE_LOGGING:
                logger.debug(f"Beacon: SSID={ssid}, BSSID={bssid}, "
                           f"Channel={channel}, Band={frequency_band}")

        except Exception as e:
            logger.error(f"Error handling beacon: {e}", exc_info=True)

    def start_capture(self):
        """Start packet capture in a separate thread."""
        if not SCAPY_AVAILABLE:
            logger.error("Scapy not available - cannot start capture")
            return

        if self.running:
            logger.warning("Capture already running")
            return

        self.running = True

        def capture_loop():
            """Capture loop running in separate thread."""
            try:
                logger.info(f"Starting packet capture on {self.interface}...")

                sniff(
                    iface=self.interface,
                    prn=self._packet_handler,
                    store=False,
                    stop_filter=lambda x: not self.running
                )

            except Exception as e:
                logger.error(f"Error in capture loop: {e}", exc_info=True)
                self.running = False

        self.capture_thread = threading.Thread(
            target=capture_loop,
            name="WiFiCaptureThread",
            daemon=True
        )
        self.capture_thread.start()

        logger.info("Packet capture started")

    def stop_capture(self):
        """Stop packet capture."""
        if not self.running:
            return

        logger.info("Stopping packet capture...")
        self.running = False

        if self.capture_thread:
            self.capture_thread.join(timeout=5)

        logger.info("Packet capture stopped")

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get monitoring statistics.

        Returns:
            Dict with statistics
        """
        return {
            'running': self.running,
            'monitor_mode': self.monitor_mode_enabled,
            'packets_captured': self.packets_captured,
            'probe_requests': self.probe_requests,
            'beacons': self.beacons,
            'queue_size': self.packet_queue.qsize()
        }

    def register_probe_callback(self, callback: Callable):
        """
        Register callback for probe request packets.

        Args:
            callback: Function to call with probe data dict
        """
        self.probe_callback = callback
        logger.info("Probe request callback registered")

    def register_beacon_callback(self, callback: Callable):
        """
        Register callback for beacon packets.

        Args:
            callback: Function to call with network data dict
        """
        self.beacon_callback = callback
        logger.info("Beacon callback registered")


class NetworkScanner:
    """Active WiFi network scanner (alternative to passive monitoring)."""

    def __init__(self, interface: str = None):
        """
        Initialize network scanner.

        Args:
            interface: WiFi interface name (default: from config)
        """
        self.interface = interface or config.WIFI_INTERFACE
        logger.info(f"Network Scanner initialized for interface: {self.interface}")

    def scan_networks(self) -> list:
        """
        Scan for available WiFi networks using iwlist.

        Returns:
            List of network dictionaries
        """
        networks = []

        try:
            # Use iwlist to scan networks
            result = subprocess.run(
                ['sudo', 'iwlist', self.interface, 'scan'],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode != 0:
                logger.error(f"iwlist scan failed: {result.stderr}")
                return networks

            # Parse iwlist output
            current_network = {}
            for line in result.stdout.split('\n'):
                line = line.strip()

                if 'Cell ' in line and 'Address:' in line:
                    # New network found, save previous if exists
                    if current_network:
                        networks.append(current_network)
                    # Start new network
                    bssid = line.split('Address: ')[1].strip()
                    current_network = {
                        'bssid': bssid,
                        'timestamp': int(datetime.now().timestamp())
                    }

                elif 'ESSID:' in line:
                    ssid = line.split('ESSID:')[1].strip('"')
                    current_network['ssid'] = ssid

                elif 'Channel:' in line:
                    channel = int(line.split('Channel:')[1].strip())
                    current_network['channel'] = channel

                    # Determine band from channel
                    if 1 <= channel <= 14:
                        current_network['frequency_band'] = '2.4GHz'
                    elif 36 <= channel <= 165:
                        current_network['frequency_band'] = '5GHz'

                elif 'Quality=' in line and 'Signal level=' in line:
                    # Extract signal level
                    signal_part = line.split('Signal level=')[1]
                    rssi = int(signal_part.split(' ')[0])
                    current_network['rssi'] = rssi

                elif 'Encryption key:' in line:
                    if 'on' in line:
                        current_network['encryption'] = 'WPA/WPA2'
                    else:
                        current_network['encryption'] = 'Open'

            # Add last network
            if current_network:
                networks.append(current_network)

            logger.info(f"Scanned {len(networks)} networks")

        except subprocess.TimeoutExpired:
            logger.error("Network scan timed out")
        except Exception as e:
            logger.error(f"Error scanning networks: {e}", exc_info=True)

        return networks


# Test function
if __name__ == '__main__':
    print("Testing WiFi Monitor...")

    monitor = WiFiMonitor()

    # Print statistics
    stats = monitor.get_statistics()
    print(f"Monitor Statistics: {stats}")

    print("\nNote: Actual packet capture requires:")
    print("  - sudo privileges")
    print("  - Monitor mode support")
    print("  - Scapy library")
    print("  - Running on Raspberry Pi with WiFi interface")
