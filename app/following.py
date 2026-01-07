"""
WiFi Desk Plumbus - Following Detection Module

This module detects devices that follow you across different locations.
The core insight: If a device appears at multiple locations that YOU visit,
it might be following you!

Implements:
- Cross-location device tracking
- Correlation scoring algorithm
- Alert generation for suspicious devices
- Device whitelist management
- Temporal analysis (did device appear at multiple locations recently?)
"""

import logging
import time
from typing import Dict, List, Set, Optional, Tuple, Any
from datetime import datetime, timedelta
from collections import defaultdict

import config
from app.database import get_db

logger = logging.getLogger(__name__)


class DeviceObservation:
    """Represents an observation of a device at a specific location."""

    def __init__(self, device_id: str, location_id: str, timestamp: int):
        """
        Initialize device observation.

        Args:
            device_id: Device fingerprint ID
            location_id: Location ID
            timestamp: Unix timestamp
        """
        self.device_id = device_id
        self.location_id = location_id
        self.timestamp = timestamp


class FollowingDetector:
    """
    Detects devices that appear to be following you across locations.

    The algorithm works by:
    1. Tracking which devices appear at each location
    2. When location changes, checking if any devices from previous location
       also appear at the new location
    3. Calculating a "correlation score" based on:
       - How many locations overlap
       - How close in time the appearances are
       - How unlikely the overlap is (rare devices score higher)
    4. Generating alerts when correlation score exceeds threshold
    """

    def __init__(self):
        """Initialize following detector."""
        self.correlation_threshold = config.FOLLOWING_CORRELATION_THRESHOLD
        self.time_window_hours = config.FOLLOWING_TIME_WINDOW_HOURS
        self.min_locations_overlap = config.MIN_LOCATIONS_FOR_FOLLOWING

        # Track device observations
        # device_id -> List[DeviceObservation]
        self.device_observations: Dict[str, List[DeviceObservation]] = defaultdict(list)

        # Whitelist of known devices (won't generate alerts)
        self.whitelist: Set[str] = set()

        # Track location history
        # List of (location_id, timestamp) tuples
        self.location_history: List[Tuple[str, int]] = []

        # Current location
        self.current_location_id: Optional[str] = None

        logger.info("FollowingDetector initialized")
        logger.info(f"Correlation threshold: {self.correlation_threshold}")
        logger.info(f"Time window: {self.time_window_hours} hours")
        logger.info(f"Min locations for following: {self.min_locations_overlap}")

    def add_device_observation(self, device_id: str, location_id: str, timestamp: int):
        """
        Record that a device was seen at a location.

        Args:
            device_id: Device fingerprint ID
            location_id: Location ID
            timestamp: Unix timestamp
        """
        observation = DeviceObservation(device_id, location_id, timestamp)
        self.device_observations[device_id].append(observation)

        # Keep only recent observations (within time window)
        cutoff_time = timestamp - (self.time_window_hours * 3600)
        self.device_observations[device_id] = [
            obs for obs in self.device_observations[device_id]
            if obs.timestamp >= cutoff_time
        ]

        logger.debug(f"Device {device_id[:8]} observed at location {location_id[:8]}")

    def update_location(self, location_id: str, timestamp: int):
        """
        Update current location and check for following devices.

        Args:
            location_id: New location ID
            timestamp: Unix timestamp

        Returns:
            List of alerts for suspicious devices
        """
        # Don't process if same location
        if location_id == self.current_location_id:
            return []

        logger.info(f"🛸 Location changed: {location_id[:8]}")

        # Add to location history
        self.location_history.append((location_id, timestamp))

        # Keep only recent history
        cutoff_time = timestamp - (self.time_window_hours * 3600)
        self.location_history = [
            (loc_id, ts) for loc_id, ts in self.location_history
            if ts >= cutoff_time
        ]

        # Check for following devices
        alerts = []
        if self.current_location_id is not None:
            alerts = self._detect_following_devices(
                self.current_location_id,
                location_id,
                timestamp
            )

        # Update current location
        self.current_location_id = location_id

        return alerts

    def _detect_following_devices(self, old_location: str, new_location: str,
                                   timestamp: int) -> List[Dict[str, Any]]:
        """
        Detect devices that appear at both old and new location.

        Args:
            old_location: Previous location ID
            new_location: New location ID
            timestamp: Current timestamp

        Returns:
            List of alert dictionaries
        """
        alerts = []

        # Get devices seen at old location (recent)
        cutoff_time = timestamp - (self.time_window_hours * 3600)

        devices_at_old = set()
        for device_id, observations in self.device_observations.items():
            for obs in observations:
                if obs.location_id == old_location and obs.timestamp >= cutoff_time:
                    devices_at_old.add(device_id)
                    break

        # Check each device for correlation
        for device_id in devices_at_old:
            # Skip whitelisted devices
            if device_id in self.whitelist:
                continue

            # Calculate correlation score
            score = self._calculate_correlation_score(device_id, timestamp)

            if score >= self.correlation_threshold:
                logger.warning(f"🚨 Suspicious device detected: {device_id[:8]} (score: {score:.2f})")

                alert = {
                    'device_id': device_id,
                    'correlation_score': score,
                    'locations': self._get_device_locations(device_id),
                    'timestamp': timestamp,
                    'alert_type': 'following_device'
                }

                alerts.append(alert)

        return alerts

    def _calculate_correlation_score(self, device_id: str, current_time: int) -> float:
        """
        Calculate correlation score for a device.

        The score is based on:
        - Number of locations where device and user overlapped
        - Temporal proximity (recent appearances score higher)
        - Rarity (devices seen at fewer total locations score higher)

        Args:
            device_id: Device fingerprint ID
            current_time: Current timestamp

        Returns:
            Correlation score (0.0 to 1.0+)
        """
        observations = self.device_observations.get(device_id, [])

        if not observations:
            return 0.0

        # Get locations where device was seen
        device_locations = set(obs.location_id for obs in observations)

        # Get locations where user has been
        user_locations = set(loc_id for loc_id, _ in self.location_history)

        # Calculate overlap
        overlap = device_locations & user_locations
        overlap_count = len(overlap)

        if overlap_count < self.min_locations_overlap:
            return 0.0

        # Base score: percentage of overlap
        base_score = overlap_count / len(user_locations) if user_locations else 0

        # Temporal bonus: reward recent appearances
        recent_count = sum(
            1 for obs in observations
            if current_time - obs.timestamp < 3600  # Last hour
        )
        temporal_bonus = min(recent_count * 0.1, 0.3)  # Max +0.3

        # Rarity bonus: devices seen at fewer locations are more suspicious
        total_device_locations = len(device_locations)
        if total_device_locations <= 2:
            rarity_bonus = 0.2
        elif total_device_locations <= 3:
            rarity_bonus = 0.1
        else:
            rarity_bonus = 0.0

        score = base_score + temporal_bonus + rarity_bonus

        return min(score, 1.0)  # Cap at 1.0

    def _get_device_locations(self, device_id: str) -> List[str]:
        """
        Get list of locations where device was observed.

        Args:
            device_id: Device fingerprint ID

        Returns:
            List of location IDs
        """
        observations = self.device_observations.get(device_id, [])
        locations = list(set(obs.location_id for obs in observations))
        return locations

    def add_to_whitelist(self, device_id: str):
        """
        Add device to whitelist (won't generate alerts).

        Args:
            device_id: Device fingerprint ID
        """
        self.whitelist.add(device_id)
        logger.info(f"Device {device_id[:8]} added to whitelist")

    def remove_from_whitelist(self, device_id: str):
        """
        Remove device from whitelist.

        Args:
            device_id: Device fingerprint ID
        """
        self.whitelist.discard(device_id)
        logger.info(f"Device {device_id[:8]} removed from whitelist")

    def is_whitelisted(self, device_id: str) -> bool:
        """
        Check if device is whitelisted.

        Args:
            device_id: Device fingerprint ID

        Returns:
            True if whitelisted
        """
        return device_id in self.whitelist

    def save_alert(self, alert: Dict[str, Any]):
        """
        Save alert to database.

        Args:
            alert: Alert dictionary
        """
        try:
            db = get_db()

            db.add_alert(
                alert_type=alert['alert_type'],
                device_fingerprint_id=alert['device_id'],
                correlation_score=alert['correlation_score'],
                timestamp=alert['timestamp'],
                details=f"Device seen at {len(alert['locations'])} locations"
            )

            logger.info(f"Alert saved for device {alert['device_id'][:8]}")

        except Exception as e:
            logger.error(f"Error saving alert: {e}", exc_info=True)

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get following detection statistics.

        Returns:
            Dictionary with statistics
        """
        total_devices = len(self.device_observations)
        whitelisted_devices = len(self.whitelist)

        # Count devices at multiple locations
        multi_location_devices = sum(
            1 for obs_list in self.device_observations.values()
            if len(set(obs.location_id for obs in obs_list)) >= 2
        )

        return {
            'total_tracked_devices': total_devices,
            'whitelisted_devices': whitelisted_devices,
            'multi_location_devices': multi_location_devices,
            'correlation_threshold': self.correlation_threshold,
            'time_window_hours': self.time_window_hours,
            'location_history_count': len(self.location_history)
        }

    def load_whitelist_from_database(self):
        """Load whitelist from database."""
        try:
            db = get_db()
            devices = db.get_all_devices(status='known')

            for device in devices:
                self.whitelist.add(device['fingerprint_id'])

            logger.info(f"Loaded {len(self.whitelist)} whitelisted devices from database")

        except Exception as e:
            logger.error(f"Error loading whitelist: {e}", exc_info=True)


# Singleton instance
_following_detector_instance: Optional[FollowingDetector] = None


def get_following_detector() -> FollowingDetector:
    """
    Get the global FollowingDetector instance.

    Returns:
        FollowingDetector instance
    """
    global _following_detector_instance

    if _following_detector_instance is None:
        _following_detector_instance = FollowingDetector()

    return _following_detector_instance


def init_following_detector() -> FollowingDetector:
    """
    Initialize the global FollowingDetector.

    Returns:
        FollowingDetector instance
    """
    global _following_detector_instance

    _following_detector_instance = FollowingDetector()

    # Load whitelist from database
    _following_detector_instance.load_whitelist_from_database()

    logger.info("FollowingDetector initialized and ready")

    return _following_detector_instance


# Test function
if __name__ == '__main__':
    print("Testing Following Detection...")
    print()

    detector = FollowingDetector()
    print(f"Detector created")

    # Simulate user at Home
    print("\n1. User at Home location")
    detector.update_location("home_loc_001", int(time.time()))

    # Device A and B at Home
    now = int(time.time())
    detector.add_device_observation("device_a", "home_loc_001", now)
    detector.add_device_observation("device_b", "home_loc_001", now)
    print("  - Device A and B observed at Home")

    # Simulate movement to Office (5 minutes later)
    time.sleep(1)  # Simulate time passing
    now = int(time.time())
    print("\n2. User moves to Office location")
    alerts = detector.update_location("office_loc_002", now)

    # Only Device A follows to Office (suspicious!)
    detector.add_device_observation("device_a", "office_loc_002", now)
    print("  - Device A observed at Office (suspicious!)")

    # Device B stays at Home (normal)
    print("  - Device B not at Office (normal)")

    # Check for alerts
    print("\n3. Checking for following devices...")
    score_a = detector._calculate_correlation_score("device_a", now)
    score_b = detector._calculate_correlation_score("device_b", now)

    print(f"  - Device A correlation score: {score_a:.2f}")
    print(f"  - Device B correlation score: {score_b:.2f}")

    if score_a >= detector.correlation_threshold:
        print(f"  ✓ Device A flagged as suspicious!")
    else:
        print(f"  ○ Device A score below threshold")

    # Print statistics
    print("\nStatistics:")
    stats = detector.get_statistics()
    for key, value in stats.items():
        print(f"  {key}: {value}")

    print("\nFollowing Detection tests complete!")
