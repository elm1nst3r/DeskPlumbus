"""
WiFi Desk Plumbus - Location Detection Module

This module handles location fingerprinting using visible WiFi networks (BSSIDs).
Similar to device fingerprinting, but for physical locations!

Implements:
- Location fingerprinting using BSSID pools
- Jaccard similarity for location matching
- Automatic location detection at boot
- Location tracking and management
- Cross-location device tracking

The key insight: Different physical locations have different sets of visible WiFi
networks. By tracking which BSSIDs we can see, we can fingerprint locations and
detect when we're in the same place again - even if we moved the Plumbus!
"""

import logging
import hashlib
import json
from typing import Set, List, Dict, Any, Optional, Tuple
from datetime import datetime
from collections import defaultdict

import config
from app.database import get_db

logger = logging.getLogger(__name__)


class BSSIDPool:
    """Represents a collection of BSSIDs (WiFi access points) visible at a location."""

    def __init__(self, bssids: Optional[Set[str]] = None):
        """
        Initialize BSSID pool.

        Args:
            bssids: Set of BSSID strings (MAC addresses of access points)
        """
        self.bssids: Set[str] = bssids or set()
        self.bssid_details: Dict[str, Dict[str, Any]] = {}  # BSSID -> {ssid, rssi, etc}
        self.first_seen = int(datetime.now().timestamp())
        self.last_updated = int(datetime.now().timestamp())

    def add_bssid(self, bssid: str, ssid: str = "", rssi: int = -100):
        """
        Add a BSSID to the pool with optional details.

        Args:
            bssid: BSSID (access point MAC address)
            ssid: Network name (optional)
            rssi: Signal strength (optional)
        """
        if not bssid or bssid == "":
            return

        self.bssids.add(bssid)

        # Update details, keeping strongest signal
        if bssid not in self.bssid_details or rssi > self.bssid_details[bssid].get('rssi', -100):
            self.bssid_details[bssid] = {
                'ssid': ssid,
                'rssi': rssi,
                'last_seen': int(datetime.now().timestamp())
            }

        self.last_updated = int(datetime.now().timestamp())

    def get_bssids(self) -> Set[str]:
        """Get set of all BSSIDs in pool."""
        return self.bssids.copy()

    def get_strong_bssids(self, rssi_threshold: int = -70) -> Set[str]:
        """
        Get BSSIDs with strong signal (more stable for fingerprinting).

        Args:
            rssi_threshold: Minimum RSSI (default: -70 dBm)

        Returns:
            Set of BSSIDs with RSSI above threshold
        """
        return {
            bssid for bssid, details in self.bssid_details.items()
            if details.get('rssi', -100) >= rssi_threshold
        }

    def size(self) -> int:
        """Get number of unique BSSIDs in pool."""
        return len(self.bssids)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'bssids': list(self.bssids),
            'bssid_details': self.bssid_details,
            'first_seen': self.first_seen,
            'last_updated': self.last_updated,
            'size': self.size()
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'BSSIDPool':
        """Create BSSIDPool from dictionary."""
        pool = cls(set(data.get('bssids', [])))
        pool.bssid_details = data.get('bssid_details', {})
        pool.first_seen = data.get('first_seen', int(datetime.now().timestamp()))
        pool.last_updated = data.get('last_updated', int(datetime.now().timestamp()))
        return pool


def calculate_location_similarity(pool_a: Set[str], pool_b: Set[str]) -> float:
    """
    Calculate Jaccard similarity between two BSSID pools.

    This is the same algorithm as device fingerprinting, but applied to locations.

    Args:
        pool_a: First BSSID set
        pool_b: Second BSSID set

    Returns:
        float: Similarity score between 0.0 and 1.0

    Example:
        >>> loc_a = {"aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02", "aa:bb:cc:dd:ee:03"}
        >>> loc_b = {"aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02", "aa:bb:cc:dd:ee:04"}
        >>> calculate_location_similarity(loc_a, loc_b)
        0.5  # 2 common BSSIDs, 4 total unique BSSIDs = 2/4
    """
    if not pool_a or not pool_b:
        return 0.0

    intersection = len(pool_a & pool_b)
    union = len(pool_a | pool_b)

    if union == 0:
        return 0.0

    return intersection / union


def generate_location_id(bssid_pool: Set[str], name: Optional[str] = None) -> str:
    """
    Generate a unique location ID from a BSSID pool.

    Args:
        bssid_pool: Set of BSSIDs
        name: Optional location name to include in hash

    Returns:
        str: Hex string location ID
    """
    # Sort BSSIDs for consistent hashing
    sorted_bssids = sorted(list(bssid_pool))

    # Create hash from BSSIDs (and optional name)
    if name:
        hash_input = f"{name}:{json.dumps(sorted_bssids)}"
    else:
        hash_input = json.dumps(sorted_bssids)

    location_hash = hashlib.sha256(hash_input.encode()).hexdigest()

    # Return first 16 characters for readability
    return location_hash[:16]


class Location:
    """Represents a physical location fingerprinted by visible WiFi networks."""

    def __init__(self, location_id: str, bssid_pool: BSSIDPool,
                 name: Optional[str] = None):
        """
        Initialize location.

        Args:
            location_id: Unique identifier
            bssid_pool: BSSIDPool object
            name: Human-friendly location name (e.g., "Home", "Office")
        """
        self.location_id = location_id
        self.bssid_pool = bssid_pool
        self.name = name or f"Location {location_id[:8]}"
        self.first_detected = int(datetime.now().timestamp())
        self.last_detected = int(datetime.now().timestamp())
        self.detection_count = 0
        self.notes: Optional[str] = None

    def update_last_detected(self):
        """Update last detected timestamp and increment count."""
        self.last_detected = int(datetime.now().timestamp())
        self.detection_count += 1

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'location_id': self.location_id,
            'name': self.name,
            'bssid_pool': self.bssid_pool.to_dict(),
            'first_detected': self.first_detected,
            'last_detected': self.last_detected,
            'detection_count': self.detection_count,
            'notes': self.notes
        }


class LocationDetector:
    """Detects and manages physical locations using WiFi network fingerprints."""

    def __init__(self):
        """Initialize location detector."""
        self.locations: Dict[str, Location] = {}
        self.current_location_id: Optional[str] = None
        self.similarity_threshold = config.LOCATION_SIMILARITY_THRESHOLD
        self.min_bssids_for_location = config.MIN_BSSIDS_FOR_LOCATION

        logger.info("LocationDetector initialized")
        logger.info(f"Location similarity threshold: {self.similarity_threshold * 100}%")
        logger.info(f"Min BSSIDs for location: {self.min_bssids_for_location}")

    def find_matching_location(self, bssid_pool: Set[str]) -> Optional[Tuple[str, float]]:
        """
        Find existing location that matches the given BSSID pool.

        Args:
            bssid_pool: Set of BSSIDs to match

        Returns:
            Tuple of (location_id, similarity_score) or None if no match
        """
        if len(bssid_pool) < self.min_bssids_for_location:
            logger.debug(f"BSSID pool too small for matching: {len(bssid_pool)} BSSIDs")
            return None

        best_match_id = None
        best_similarity = 0.0

        # Compare against all existing locations
        for location_id, location in self.locations.items():
            existing_pool = location.bssid_pool.get_bssids()

            # Calculate similarity
            similarity = calculate_location_similarity(bssid_pool, existing_pool)

            # Track best match
            if similarity > best_similarity:
                best_similarity = similarity
                best_match_id = location_id

        # Return match if above threshold
        if best_similarity >= self.similarity_threshold:
            logger.info(f"Location match found: {self.locations[best_match_id].name} "
                       f"({best_similarity * 100:.1f}% similarity)")
            return (best_match_id, best_similarity)

        logger.debug(f"No location match found. Best similarity: {best_similarity * 100:.1f}%")
        return None

    def create_location(self, bssid_pool: Set[str], name: Optional[str] = None) -> Location:
        """
        Create a new location fingerprint.

        Args:
            bssid_pool: Set of BSSIDs
            name: Optional location name

        Returns:
            Location object
        """
        # Generate location ID
        location_id = generate_location_id(bssid_pool, name)

        # Create BSSID pool object
        pool_obj = BSSIDPool(bssid_pool)

        # Create location
        location = Location(
            location_id=location_id,
            bssid_pool=pool_obj,
            name=name
        )

        # Store location
        self.locations[location_id] = location

        logger.info(f"Created new location: {location.name} with {len(bssid_pool)} BSSIDs")
        return location

    def detect_current_location(self, network_observations: List[Dict[str, Any]]) -> Optional[str]:
        """
        Detect current location from network observations.

        Args:
            network_observations: List of network observation dicts with 'bssid' key

        Returns:
            location_id if detected, None otherwise
        """
        if not network_observations:
            logger.debug("No network observations for location detection")
            return None

        # Extract BSSIDs from observations
        current_bssids = {obs['bssid'] for obs in network_observations if obs.get('bssid')}

        if len(current_bssids) < self.min_bssids_for_location:
            logger.debug(f"Not enough BSSIDs for location detection: {len(current_bssids)}")
            return None

        # Try to match existing location
        match = self.find_matching_location(current_bssids)

        if match:
            location_id, similarity = match
            location = self.locations[location_id]

            # Update location with new BSSIDs
            for obs in network_observations:
                if obs.get('bssid'):
                    location.bssid_pool.add_bssid(
                        bssid=obs['bssid'],
                        ssid=obs.get('ssid', ''),
                        rssi=obs.get('rssi', -100)
                    )

            location.update_last_detected()
            self.current_location_id = location_id

            logger.info(f"🛸 Plumbus detected location: {location.name}")
            return location_id

        # No match - this might be a new location
        logger.info(f"Unknown location detected ({len(current_bssids)} BSSIDs visible)")
        return None

    def get_current_location(self) -> Optional[Location]:
        """Get current location object."""
        if self.current_location_id and self.current_location_id in self.locations:
            return self.locations[self.current_location_id]
        return None

    def set_location_name(self, location_id: str, name: str):
        """
        Set human-friendly name for a location.

        Args:
            location_id: Location ID
            name: New name
        """
        if location_id in self.locations:
            self.locations[location_id].name = name
            logger.info(f"Updated location name: {name}")

    def load_from_database(self):
        """Load existing locations from database."""
        try:
            db = get_db()
            locations_data = db.get_all_locations()

            loaded_count = 0
            for loc_data in locations_data:
                try:
                    # Parse BSSID pool
                    bssid_pool_data = json.loads(loc_data.get('bssid_pool', '[]'))
                    bssid_pool = BSSIDPool(set(bssid_pool_data))

                    # Create location
                    location = Location(
                        location_id=loc_data['location_id'],
                        bssid_pool=bssid_pool,
                        name=loc_data.get('name', f"Location {loc_data['location_id'][:8]}")
                    )

                    location.first_detected = loc_data.get('first_detected', location.first_detected)
                    location.last_detected = loc_data.get('last_detected', location.last_detected)
                    location.notes = loc_data.get('notes')

                    # Store location
                    self.locations[location.location_id] = location
                    loaded_count += 1

                except Exception as e:
                    logger.error(f"Error loading location {loc_data.get('id')}: {e}")

            logger.info(f"Loaded {loaded_count} locations from database")

        except Exception as e:
            logger.error(f"Error loading locations from database: {e}", exc_info=True)

    def save_location_to_database(self, location: Location):
        """
        Save location to database.

        Args:
            location: Location to save
        """
        try:
            db = get_db()

            # Check if exists
            existing = db.get_location(location.location_id)

            bssid_pool_list = list(location.bssid_pool.get_bssids())

            if existing:
                # Update existing
                db.update_location(
                    location.location_id,
                    name=location.name,
                    bssid_pool=json.dumps(bssid_pool_list),
                    last_detected=location.last_detected,
                    notes=location.notes
                )
            else:
                # Create new
                db.add_location(
                    location_id=location.location_id,
                    name=location.name,
                    bssid_pool=bssid_pool_list,
                    timestamp=location.first_detected
                )

        except Exception as e:
            logger.error(f"Error saving location to database: {e}", exc_info=True)

    def get_statistics(self) -> Dict[str, Any]:
        """Get location detection statistics."""
        total_bssids = sum(loc.bssid_pool.size() for loc in self.locations.values())
        avg_bssids = total_bssids / len(self.locations) if self.locations else 0

        current_location = self.get_current_location()

        return {
            'total_locations': len(self.locations),
            'current_location': current_location.name if current_location else None,
            'current_location_id': self.current_location_id,
            'average_bssids_per_location': round(avg_bssids, 1),
            'similarity_threshold': self.similarity_threshold
        }


# Singleton instance
_location_detector_instance: Optional[LocationDetector] = None


def get_location_detector() -> LocationDetector:
    """
    Get the global LocationDetector instance.

    Returns:
        LocationDetector instance
    """
    global _location_detector_instance

    if _location_detector_instance is None:
        _location_detector_instance = LocationDetector()

    return _location_detector_instance


def init_location_detector() -> LocationDetector:
    """
    Initialize the global LocationDetector.

    Returns:
        LocationDetector instance
    """
    global _location_detector_instance

    _location_detector_instance = LocationDetector()

    # Load existing locations from database
    _location_detector_instance.load_from_database()

    logger.info("LocationDetector initialized and ready")

    return _location_detector_instance


# Test function
if __name__ == '__main__':
    print("Testing Location Detection...")
    print()

    # Create detector
    detector = LocationDetector()
    print(f"Detector created")

    # Simulate network observations at "Home"
    print("\nSimulating WiFi networks at Home...")
    home_networks = [
        {'bssid': 'aa:bb:cc:dd:ee:01', 'ssid': 'HomeWiFi', 'rssi': -45},
        {'bssid': 'aa:bb:cc:dd:ee:02', 'ssid': 'HomeWiFi_5G', 'rssi': -50},
        {'bssid': 'aa:bb:cc:dd:ee:03', 'ssid': 'NeighborNet', 'rssi': -75},
        {'bssid': 'aa:bb:cc:dd:ee:04', 'ssid': 'AnotherNeighbor', 'rssi': -80},
    ]

    # First detection at Home (should create new location)
    location_id = detector.detect_current_location(home_networks)
    if not location_id:
        home_bssids = {net['bssid'] for net in home_networks}
        home_location = detector.create_location(home_bssids, "Home")
        detector.current_location_id = home_location.location_id
        print(f"  Created new location: {home_location.name}")

    # Simulate moving to Office
    print("\nSimulating WiFi networks at Office...")
    office_networks = [
        {'bssid': '11:22:33:44:55:01', 'ssid': 'CorpNet', 'rssi': -40},
        {'bssid': '11:22:33:44:55:02', 'ssid': 'CorpNet_5G', 'rssi': -45},
        {'bssid': '11:22:33:44:55:03', 'ssid': 'CorpGuest', 'rssi': -50},
        {'bssid': '11:22:33:44:55:04', 'ssid': 'Starbucks', 'rssi': -70},
    ]

    office_location_id = detector.detect_current_location(office_networks)
    if not office_location_id:
        office_bssids = {net['bssid'] for net in office_networks}
        office_location = detector.create_location(office_bssids, "Office")
        detector.current_location_id = office_location.location_id
        print(f"  Created new location: {office_location.name}")

    # Return to Home (should detect existing location)
    print("\nReturning to Home...")
    detected = detector.detect_current_location(home_networks)
    if detected:
        print(f"  ✓ Successfully detected: {detector.locations[detected].name}")
    else:
        print("  ✗ Failed to detect location")

    # Print statistics
    print("\nStatistics:")
    stats = detector.get_statistics()
    for key, value in stats.items():
        print(f"  {key}: {value}")

    print("\nLocation Detection tests complete!")
