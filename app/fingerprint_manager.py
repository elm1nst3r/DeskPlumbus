"""
WiFi Desk Plumbus - Fingerprint Manager Module

This module integrates WiFi monitoring with device fingerprinting.
It processes probe requests and builds SSID pools to track devices
despite MAC randomization.

Implements:
- Integration between WiFiMonitor and FingerprintMatcher
- Probe request aggregation per MAC address
- Automatic fingerprint creation and matching
- Real-time device tracking
"""

import logging
import threading
from datetime import datetime
from typing import Dict, Set, Optional
from collections import defaultdict

import config
from app.fingerprint import FingerprintMatcher, SSIDPool, DeviceFingerprint
from app.monitor import WiFiMonitor
from app.database import get_db
from app.location import LocationDetector

logger = logging.getLogger(__name__)


class FingerprintManager:
    """
    Manages device fingerprinting by processing WiFi probe requests.

    This is the central coordinator that:
    1. Receives probe requests from WiFiMonitor
    2. Builds SSID pools per MAC address
    3. Matches SSID pools to existing fingerprints
    4. Creates new fingerprints when needed
    5. Persists fingerprints to database
    """

    def __init__(self, wifi_monitor: Optional[WiFiMonitor] = None,
                 location_detector: Optional[LocationDetector] = None):
        """
        Initialize fingerprint manager.

        Args:
            wifi_monitor: WiFiMonitor instance (optional, can be set later)
            location_detector: LocationDetector instance (optional, can be set later)
        """
        self.matcher = FingerprintMatcher()
        self.wifi_monitor = wifi_monitor
        self.location_detector = location_detector

        # Track SSID pools being built for each MAC address
        # MAC -> Set[SSIDs]
        self.active_pools: Dict[str, Set[str]] = defaultdict(set)

        # Track when we last processed each MAC
        # MAC -> timestamp
        self.last_seen: Dict[str, int] = {}

        # Track network observations for location detection
        # List of recent network observations (beacons)
        self.recent_networks: list = []
        self.last_location_check = 0

        # Lock for thread safety
        self.lock = threading.Lock()

        # Statistics
        self.probes_processed = 0
        self.fingerprints_created = 0
        self.fingerprints_matched = 0

        logger.info("FingerprintManager initialized")

    def set_wifi_monitor(self, wifi_monitor: WiFiMonitor):
        """
        Set WiFi monitor and register callbacks.

        Args:
            wifi_monitor: WiFiMonitor instance
        """
        self.wifi_monitor = wifi_monitor

        # Register our callback for probe requests (device fingerprinting)
        self.wifi_monitor.register_probe_callback(self.process_probe_request)

        # Register our callback for beacons (location detection)
        self.wifi_monitor.register_beacon_callback(self.process_network_observation)

        logger.info("WiFi monitor connected to FingerprintManager")

    def set_location_detector(self, location_detector: LocationDetector):
        """
        Set location detector.

        Args:
            location_detector: LocationDetector instance
        """
        self.location_detector = location_detector
        logger.info("Location detector connected to FingerprintManager")

    def load_fingerprints(self):
        """Load existing fingerprints from database."""
        logger.info("Loading fingerprints from database...")
        self.matcher.load_from_database()
        stats = self.matcher.get_statistics()
        logger.info(f"Loaded {stats['total_fingerprints']} fingerprints with "
                   f"{stats['total_mac_addresses']} MAC addresses")

    def process_probe_request(self, probe_data: Dict):
        """
        Process a probe request from WiFi monitor.

        This is called by WiFiMonitor for each probe request captured.

        Args:
            probe_data: Dictionary with keys:
                - mac_address: str
                - ssid: str
                - frequency_band: str
                - timestamp: int
        """
        try:
            with self.lock:
                self.probes_processed += 1

                mac_address = probe_data['mac_address']
                ssid = probe_data['ssid']
                timestamp = probe_data['timestamp']

                # Skip empty SSIDs (broadcast probes)
                if not ssid or ssid == "":
                    return

                # Add SSID to this MAC's pool
                self.active_pools[mac_address].add(ssid)
                self.last_seen[mac_address] = timestamp

                logger.debug(f"Probe from {mac_address} for SSID '{ssid}' "
                           f"(pool now has {len(self.active_pools[mac_address])} SSIDs)")

                # Check if we have enough SSIDs to attempt matching
                pool_size = len(self.active_pools[mac_address])

                if pool_size >= config.MIN_SSIDS_FOR_FINGERPRINT:
                    self._attempt_fingerprint_match(mac_address)

                # Store probe request in database
                self._save_probe_request(probe_data)

        except Exception as e:
            logger.error(f"Error processing probe request: {e}", exc_info=True)

    def _attempt_fingerprint_match(self, mac_address: str):
        """
        Attempt to match or create fingerprint for a MAC address.

        Args:
            mac_address: MAC address to process
        """
        try:
            current_pool = self.active_pools[mac_address]

            # First check if we already have a fingerprint for this MAC
            existing = self.matcher.get_fingerprint_by_mac(mac_address)

            if existing:
                # Update existing fingerprint with new SSIDs
                for ssid in current_pool:
                    existing.ssid_pool.add_ssid(ssid)

                existing.update_last_seen()

                # Save updated fingerprint
                self.matcher.save_fingerprint_to_database(existing)

                logger.debug(f"Updated existing fingerprint {existing.fingerprint_id} "
                           f"for MAC {mac_address}")
                return

            # No existing fingerprint for this MAC - try to match by SSID pool
            match = self.matcher.find_matching_fingerprint(current_pool)

            if match:
                # Found a matching fingerprint!
                fingerprint_id, similarity = match
                fingerprint = self.matcher.fingerprints[fingerprint_id]

                # Associate this MAC with the fingerprint
                fingerprint.add_mac_address(mac_address)

                # Update SSID pool with any new SSIDs
                for ssid in current_pool:
                    fingerprint.ssid_pool.add_ssid(ssid)

                # Update confidence based on similarity
                fingerprint.confidence = similarity

                # Save updated fingerprint
                self.matcher.save_fingerprint_to_database(fingerprint)

                self.fingerprints_matched += 1

                logger.info(f"Matched MAC {mac_address} to fingerprint {fingerprint_id} "
                          f"({similarity * 100:.1f}% similarity)")

                # Check for potential MAC randomization
                if len(fingerprint.mac_addresses) > 1:
                    logger.warning(f"🛸 Plumbus detected MAC randomization! "
                                 f"Fingerprint {fingerprint_id} now has "
                                 f"{len(fingerprint.mac_addresses)} MAC addresses")

            else:
                # No match - create new fingerprint
                fingerprint = self.matcher.create_fingerprint(current_pool, mac_address)

                # Save to database
                self.matcher.save_fingerprint_to_database(fingerprint)

                self.fingerprints_created += 1

                logger.info(f"Created new fingerprint {fingerprint.fingerprint_id} "
                          f"for MAC {mac_address} with {len(current_pool)} SSIDs")

        except Exception as e:
            logger.error(f"Error matching fingerprint: {e}", exc_info=True)

    def _save_probe_request(self, probe_data: Dict):
        """
        Save probe request to database.

        Args:
            probe_data: Probe request data
        """
        try:
            db = get_db()

            # Get fingerprint ID if we have one for this MAC
            fingerprint_id = None
            fingerprint = self.matcher.get_fingerprint_by_mac(probe_data['mac_address'])
            if fingerprint:
                fingerprint_id = fingerprint.fingerprint_id

            db.add_probe_request(
                mac_address=probe_data['mac_address'],
                ssid=probe_data['ssid'],
                frequency_band=probe_data.get('frequency_band', 'Unknown'),
                timestamp=probe_data['timestamp'],
                device_fingerprint_id=fingerprint_id
            )

        except Exception as e:
            logger.error(f"Error saving probe request: {e}", exc_info=True)

    def process_network_observation(self, network_data: Dict):
        """
        Process a network observation (beacon frame) from WiFi monitor.

        This handles Phase 3 location detection!

        Args:
            network_data: Dictionary with network information
        """
        try:
            db = get_db()

            # Add to recent networks list for location detection (Phase 3)
            with self.lock:
                self.recent_networks.append(network_data)

                # Keep only recent observations (last 30 seconds)
                now = int(datetime.now().timestamp())
                self.recent_networks = [
                    obs for obs in self.recent_networks
                    if now - obs.get('timestamp', 0) < 30
                ]

                # Attempt location detection every 10 seconds
                if self.location_detector and (now - self.last_location_check >= 10):
                    self.last_location_check = now

                    # Try to detect current location
                    detected_location_id = self.location_detector.detect_current_location(
                        self.recent_networks
                    )

                    if detected_location_id:
                        # Save location to database
                        location = self.location_detector.locations[detected_location_id]
                        self.location_detector.save_location_to_database(location)

            # Get current location if we have one
            location_id = None
            if self.location_detector and self.location_detector.current_location_id:
                location_id = self.location_detector.current_location_id

            db.add_network_observation(
                ssid=network_data.get('ssid', ''),
                bssid=network_data['bssid'],
                channel=network_data.get('channel', 0),
                frequency_band=network_data.get('frequency_band', 'Unknown'),
                rssi=network_data.get('rssi', -100),
                encryption=network_data.get('encryption', 'Unknown'),
                timestamp=network_data['timestamp'],
                location_id=location_id
            )

            if config.VERBOSE_LOGGING:
                logger.debug(f"Saved network observation: {network_data.get('ssid', 'Hidden')}")

        except Exception as e:
            logger.error(f"Error saving network observation: {e}", exc_info=True)

    def get_device_count(self) -> int:
        """Get total number of tracked devices."""
        return len(self.matcher.fingerprints)

    def get_device_list(self):
        """
        Get list of all tracked devices.

        Returns:
            List of device fingerprint dictionaries
        """
        devices = []

        with self.lock:
            for fingerprint in self.matcher.fingerprints.values():
                devices.append({
                    'fingerprint_id': fingerprint.fingerprint_id,
                    'mac_addresses': fingerprint.mac_addresses,
                    'ssid_count': fingerprint.ssid_pool.size(),
                    'top_ssids': fingerprint.ssid_pool.get_top_ssids(limit=5),
                    'first_seen': fingerprint.first_seen,
                    'last_seen': fingerprint.last_seen,
                    'confidence': fingerprint.confidence,
                    'custom_name': fingerprint.custom_name,
                    'status': fingerprint.status
                })

        # Sort by last seen (most recent first)
        devices.sort(key=lambda x: x['last_seen'], reverse=True)

        return devices

    def get_statistics(self) -> Dict:
        """
        Get fingerprinting statistics.

        Returns:
            Dictionary with statistics
        """
        with self.lock:
            matcher_stats = self.matcher.get_statistics()

            return {
                'probes_processed': self.probes_processed,
                'fingerprints_created': self.fingerprints_created,
                'fingerprints_matched': self.fingerprints_matched,
                'total_fingerprints': matcher_stats['total_fingerprints'],
                'total_mac_addresses': matcher_stats['total_mac_addresses'],
                'average_ssids_per_device': matcher_stats['average_ssids_per_device'],
                'active_pools': len(self.active_pools),
                'similarity_threshold': matcher_stats['similarity_threshold']
            }

    def cleanup_stale_pools(self, max_age_seconds: int = 3600):
        """
        Clean up SSID pools for MACs we haven't seen recently.

        Args:
            max_age_seconds: Maximum age before cleanup (default: 1 hour)
        """
        now = int(datetime.now().timestamp())
        stale_macs = []

        with self.lock:
            for mac, last_time in self.last_seen.items():
                if now - last_time > max_age_seconds:
                    stale_macs.append(mac)

            for mac in stale_macs:
                if mac in self.active_pools:
                    del self.active_pools[mac]
                if mac in self.last_seen:
                    del self.last_seen[mac]

            if stale_macs:
                logger.info(f"Cleaned up {len(stale_macs)} stale SSID pools")


# Singleton instance
_fingerprint_manager_instance: Optional[FingerprintManager] = None


def get_fingerprint_manager() -> FingerprintManager:
    """
    Get the global FingerprintManager instance.

    Returns:
        FingerprintManager instance
    """
    global _fingerprint_manager_instance

    if _fingerprint_manager_instance is None:
        _fingerprint_manager_instance = FingerprintManager()

    return _fingerprint_manager_instance


def init_fingerprint_manager(wifi_monitor: Optional[WiFiMonitor] = None,
                            location_detector: Optional[LocationDetector] = None) -> FingerprintManager:
    """
    Initialize the global FingerprintManager.

    Args:
        wifi_monitor: WiFiMonitor instance to connect
        location_detector: LocationDetector instance to connect (Phase 3)

    Returns:
        FingerprintManager instance
    """
    global _fingerprint_manager_instance

    _fingerprint_manager_instance = FingerprintManager(wifi_monitor, location_detector)

    # Load existing fingerprints from database
    _fingerprint_manager_instance.load_fingerprints()

    logger.info("FingerprintManager initialized and ready")

    return _fingerprint_manager_instance


# Test function
if __name__ == '__main__':
    print("Testing Fingerprint Manager...")
    print()

    # Create manager
    manager = FingerprintManager()
    print(f"Manager created")

    # Simulate some probe requests
    print("\nSimulating probe requests...")

    # Device 1: iPhone with home and work networks
    for _ in range(3):
        manager.process_probe_request({
            'mac_address': 'aa:bb:cc:dd:ee:01',
            'ssid': 'HomeWiFi',
            'frequency_band': '2.4GHz',
            'timestamp': int(datetime.now().timestamp())
        })

    manager.process_probe_request({
        'mac_address': 'aa:bb:cc:dd:ee:01',
        'ssid': 'WorkNet',
        'frequency_band': '5GHz',
        'timestamp': int(datetime.now().timestamp())
    })

    manager.process_probe_request({
        'mac_address': 'aa:bb:cc:dd:ee:01',
        'ssid': 'Starbucks',
        'frequency_band': '2.4GHz',
        'timestamp': int(datetime.now().timestamp())
    })

    # Device 1 with randomized MAC (should match to same fingerprint)
    print("\nSimulating MAC randomization...")
    manager.process_probe_request({
        'mac_address': 'aa:bb:cc:dd:ee:99',  # Different MAC
        'ssid': 'HomeWiFi',
        'frequency_band': '2.4GHz',
        'timestamp': int(datetime.now().timestamp())
    })

    manager.process_probe_request({
        'mac_address': 'aa:bb:cc:dd:ee:99',
        'ssid': 'WorkNet',
        'frequency_band': '5GHz',
        'timestamp': int(datetime.now().timestamp())
    })

    manager.process_probe_request({
        'mac_address': 'aa:bb:cc:dd:ee:99',
        'ssid': 'Starbucks',
        'frequency_band': '2.4GHz',
        'timestamp': int(datetime.now().timestamp())
    })

    # Print statistics
    print("\nStatistics:")
    stats = manager.get_statistics()
    for key, value in stats.items():
        print(f"  {key}: {value}")

    print("\nDevices:")
    devices = manager.get_device_list()
    for device in devices:
        print(f"  Fingerprint: {device['fingerprint_id']}")
        print(f"    MACs: {device['mac_addresses']}")
        print(f"    SSIDs: {device['top_ssids']}")
        print()

    print("Fingerprint Manager tests complete!")
