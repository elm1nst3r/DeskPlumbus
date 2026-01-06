"""
WiFi Desk Plumbus - Fingerprinting Module

This module handles SSID pool fingerprinting using Jaccard similarity.
This is the key innovation that defeats MAC randomization!

Implements:
- Jaccard similarity coefficient calculation
- SSID pool management and matching
- Device fingerprint creation and matching
- Fingerprint evolution tracking
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


class SSIDPool:
    """Represents a collection of SSIDs probed by a device."""

    def __init__(self, ssids: Optional[Set[str]] = None):
        """
        Initialize SSID pool.

        Args:
            ssids: Set of SSID strings
        """
        self.ssids: Set[str] = ssids or set()
        self.ssid_counts: Dict[str, int] = defaultdict(int)
        self.first_seen = int(datetime.now().timestamp())
        self.last_updated = int(datetime.now().timestamp())

    def add_ssid(self, ssid: str):
        """
        Add an SSID to the pool.

        Args:
            ssid: SSID string to add
        """
        if not ssid or ssid == "":
            return

        self.ssids.add(ssid)
        self.ssid_counts[ssid] += 1
        self.last_updated = int(datetime.now().timestamp())

    def get_ssids(self) -> Set[str]:
        """Get set of all SSIDs in pool."""
        return self.ssids.copy()

    def get_top_ssids(self, limit: int = None) -> List[str]:
        """
        Get most frequently probed SSIDs.

        Args:
            limit: Maximum number to return (default: all)

        Returns:
            List of SSIDs sorted by frequency
        """
        sorted_ssids = sorted(
            self.ssid_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )

        if limit:
            sorted_ssids = sorted_ssids[:limit]

        return [ssid for ssid, count in sorted_ssids]

    def size(self) -> int:
        """Get number of unique SSIDs in pool."""
        return len(self.ssids)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'ssids': list(self.ssids),
            'ssid_counts': dict(self.ssid_counts),
            'first_seen': self.first_seen,
            'last_updated': self.last_updated,
            'size': self.size()
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SSIDPool':
        """Create SSIDPool from dictionary."""
        pool = cls(set(data.get('ssids', [])))
        pool.ssid_counts = defaultdict(int, data.get('ssid_counts', {}))
        pool.first_seen = data.get('first_seen', int(datetime.now().timestamp()))
        pool.last_updated = data.get('last_updated', int(datetime.now().timestamp()))
        return pool


def calculate_jaccard_similarity(pool_a: Set[str], pool_b: Set[str]) -> float:
    """
    Calculate Jaccard similarity coefficient between two SSID pools.

    The Jaccard coefficient is defined as:
        J(A, B) = |A ∩ B| / |A ∪ B|

    This measures how similar two sets are, ranging from 0 (completely different)
    to 1 (identical).

    Args:
        pool_a: First SSID set
        pool_b: Second SSID set

    Returns:
        float: Similarity score between 0.0 and 1.0

    Example:
        >>> pool_a = {"HomeWiFi", "WorkNet", "Starbucks", "Airport"}
        >>> pool_b = {"HomeWiFi", "WorkNet", "Starbucks", "CoffeeShop"}
        >>> calculate_jaccard_similarity(pool_a, pool_b)
        0.6  # 3 common SSIDs, 5 total unique SSIDs = 3/5
    """
    if not pool_a or not pool_b:
        return 0.0

    # Calculate intersection (common SSIDs)
    intersection = len(pool_a & pool_b)

    # Calculate union (all unique SSIDs)
    union = len(pool_a | pool_b)

    # Avoid division by zero
    if union == 0:
        return 0.0

    similarity = intersection / union

    return similarity


def generate_fingerprint_id(ssid_pool: Set[str]) -> str:
    """
    Generate a unique fingerprint ID from an SSID pool.

    Uses SHA256 hash of sorted SSID list to create stable identifier.

    Args:
        ssid_pool: Set of SSIDs

    Returns:
        str: Hex string fingerprint ID
    """
    # Sort SSIDs for consistent hashing
    sorted_ssids = sorted(list(ssid_pool))

    # Create hash from JSON representation
    pool_json = json.dumps(sorted_ssids, sort_keys=True)
    fingerprint_hash = hashlib.sha256(pool_json.encode()).hexdigest()

    # Return first 16 characters for readability
    return fingerprint_hash[:16]


class DeviceFingerprint:
    """Represents a device's unique fingerprint based on SSID pool."""

    def __init__(self, fingerprint_id: str, ssid_pool: SSIDPool,
                 mac_addresses: Optional[List[str]] = None):
        """
        Initialize device fingerprint.

        Args:
            fingerprint_id: Unique identifier
            ssid_pool: SSIDPool object
            mac_addresses: List of observed MAC addresses
        """
        self.fingerprint_id = fingerprint_id
        self.ssid_pool = ssid_pool
        self.mac_addresses = mac_addresses or []
        self.first_seen = int(datetime.now().timestamp())
        self.last_seen = int(datetime.now().timestamp())
        self.confidence = 1.0
        self.custom_name: Optional[str] = None
        self.status = config.DEVICE_STATUS_NEUTRAL
        self.notes: Optional[str] = None

    def add_mac_address(self, mac_address: str):
        """Add a MAC address to this fingerprint."""
        if mac_address not in self.mac_addresses:
            self.mac_addresses.append(mac_address)
            self.last_seen = int(datetime.now().timestamp())

    def update_last_seen(self):
        """Update last seen timestamp."""
        self.last_seen = int(datetime.now().timestamp())

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'fingerprint_id': self.fingerprint_id,
            'ssid_pool': self.ssid_pool.to_dict(),
            'mac_addresses': self.mac_addresses,
            'first_seen': self.first_seen,
            'last_seen': self.last_seen,
            'confidence': self.confidence,
            'custom_name': self.custom_name,
            'status': self.status,
            'notes': self.notes
        }


class FingerprintMatcher:
    """Matches probe requests to device fingerprints using SSID pools."""

    def __init__(self):
        """Initialize fingerprint matcher."""
        self.fingerprints: Dict[str, DeviceFingerprint] = {}
        self.mac_to_fingerprint: Dict[str, str] = {}
        self.similarity_threshold = config.SIMILARITY_THRESHOLD
        self.min_ssids_for_fingerprint = config.MIN_SSIDS_FOR_FINGERPRINT

        logger.info("FingerprintMatcher initialized")
        logger.info(f"Similarity threshold: {self.similarity_threshold * 100}%")
        logger.info(f"Min SSIDs for fingerprint: {self.min_ssids_for_fingerprint}")

    def find_matching_fingerprint(self, ssid_pool: Set[str]) -> Optional[Tuple[str, float]]:
        """
        Find existing fingerprint that matches the given SSID pool.

        Args:
            ssid_pool: Set of SSIDs to match

        Returns:
            Tuple of (fingerprint_id, similarity_score) or None if no match
        """
        if len(ssid_pool) < self.min_ssids_for_fingerprint:
            logger.debug(f"SSID pool too small for matching: {len(ssid_pool)} SSIDs")
            return None

        best_match_id = None
        best_similarity = 0.0

        # Compare against all existing fingerprints
        for fingerprint_id, fingerprint in self.fingerprints.items():
            existing_pool = fingerprint.ssid_pool.get_ssids()

            # Calculate similarity
            similarity = calculate_jaccard_similarity(ssid_pool, existing_pool)

            # Track best match
            if similarity > best_similarity:
                best_similarity = similarity
                best_match_id = fingerprint_id

        # Return match if above threshold
        if best_similarity >= self.similarity_threshold:
            logger.info(f"Match found: {best_match_id} with {best_similarity * 100:.1f}% similarity")
            return (best_match_id, best_similarity)

        logger.debug(f"No match found. Best similarity: {best_similarity * 100:.1f}%")
        return None

    def create_fingerprint(self, ssid_pool: Set[str], mac_address: str) -> DeviceFingerprint:
        """
        Create a new device fingerprint.

        Args:
            ssid_pool: Set of SSIDs
            mac_address: MAC address observed

        Returns:
            DeviceFingerprint object
        """
        # Generate fingerprint ID
        fingerprint_id = generate_fingerprint_id(ssid_pool)

        # Create SSID pool object
        pool_obj = SSIDPool(ssid_pool)

        # Create fingerprint
        fingerprint = DeviceFingerprint(
            fingerprint_id=fingerprint_id,
            ssid_pool=pool_obj,
            mac_addresses=[mac_address]
        )

        # Store fingerprint
        self.fingerprints[fingerprint_id] = fingerprint
        self.mac_to_fingerprint[mac_address] = fingerprint_id

        logger.info(f"Created new fingerprint: {fingerprint_id} with {len(ssid_pool)} SSIDs")
        return fingerprint

    def update_fingerprint(self, fingerprint_id: str, ssid: str, mac_address: str):
        """
        Update an existing fingerprint with new data.

        Args:
            fingerprint_id: Fingerprint to update
            ssid: New SSID to add
            mac_address: MAC address to associate
        """
        if fingerprint_id not in self.fingerprints:
            logger.warning(f"Fingerprint {fingerprint_id} not found")
            return

        fingerprint = self.fingerprints[fingerprint_id]

        # Add SSID to pool
        fingerprint.ssid_pool.add_ssid(ssid)

        # Add MAC address if new
        fingerprint.add_mac_address(mac_address)

        # Update mapping
        self.mac_to_fingerprint[mac_address] = fingerprint_id

        logger.debug(f"Updated fingerprint {fingerprint_id}: now {fingerprint.ssid_pool.size()} SSIDs")

    def get_fingerprint_by_mac(self, mac_address: str) -> Optional[DeviceFingerprint]:
        """
        Get fingerprint associated with a MAC address.

        Args:
            mac_address: MAC address to lookup

        Returns:
            DeviceFingerprint or None
        """
        fingerprint_id = self.mac_to_fingerprint.get(mac_address)
        if fingerprint_id:
            return self.fingerprints.get(fingerprint_id)
        return None

    def load_from_database(self):
        """Load existing fingerprints from database."""
        try:
            db = get_db()
            devices = db.get_all_devices()

            loaded_count = 0
            for device_data in devices:
                try:
                    # Parse SSID pool
                    ssid_pool_data = json.loads(device_data.get('ssid_pool', '[]'))
                    ssid_pool = SSIDPool(set(ssid_pool_data))

                    # Parse MAC addresses
                    mac_addresses = json.loads(device_data.get('mac_addresses', '[]'))

                    # Create fingerprint
                    fingerprint = DeviceFingerprint(
                        fingerprint_id=device_data['fingerprint_id'],
                        ssid_pool=ssid_pool,
                        mac_addresses=mac_addresses
                    )

                    fingerprint.first_seen = device_data.get('first_seen', fingerprint.first_seen)
                    fingerprint.last_seen = device_data.get('last_seen', fingerprint.last_seen)
                    fingerprint.confidence = device_data.get('confidence', 1.0)
                    fingerprint.custom_name = device_data.get('custom_name')
                    fingerprint.status = device_data.get('status', config.DEVICE_STATUS_NEUTRAL)
                    fingerprint.notes = device_data.get('notes')

                    # Store fingerprint
                    self.fingerprints[fingerprint.fingerprint_id] = fingerprint

                    # Map MAC addresses
                    for mac in mac_addresses:
                        self.mac_to_fingerprint[mac] = fingerprint.fingerprint_id

                    loaded_count += 1

                except Exception as e:
                    logger.error(f"Error loading device {device_data.get('id')}: {e}")

            logger.info(f"Loaded {loaded_count} fingerprints from database")

        except Exception as e:
            logger.error(f"Error loading fingerprints from database: {e}", exc_info=True)

    def save_fingerprint_to_database(self, fingerprint: DeviceFingerprint):
        """
        Save fingerprint to database.

        Args:
            fingerprint: DeviceFingerprint to save
        """
        try:
            db = get_db()

            # Check if exists
            existing = db.get_device(fingerprint.fingerprint_id)

            ssid_pool_list = list(fingerprint.ssid_pool.get_ssids())

            if existing:
                # Update existing
                db.update_device(
                    fingerprint.fingerprint_id,
                    last_seen=fingerprint.last_seen,
                    ssid_pool=json.dumps(ssid_pool_list),
                    mac_addresses=json.dumps(fingerprint.mac_addresses),
                    confidence=fingerprint.confidence,
                    custom_name=fingerprint.custom_name,
                    status=fingerprint.status,
                    notes=fingerprint.notes
                )
            else:
                # Create new
                db.add_device(
                    fingerprint_id=fingerprint.fingerprint_id,
                    ssid_pool=ssid_pool_list,
                    mac_address=fingerprint.mac_addresses[0] if fingerprint.mac_addresses else "unknown",
                    timestamp=fingerprint.first_seen
                )

        except Exception as e:
            logger.error(f"Error saving fingerprint to database: {e}", exc_info=True)

    def get_statistics(self) -> Dict[str, Any]:
        """Get fingerprinting statistics."""
        total_ssids = sum(fp.ssid_pool.size() for fp in self.fingerprints.values())
        avg_ssids = total_ssids / len(self.fingerprints) if self.fingerprints else 0

        return {
            'total_fingerprints': len(self.fingerprints),
            'total_mac_addresses': len(self.mac_to_fingerprint),
            'average_ssids_per_device': round(avg_ssids, 1),
            'similarity_threshold': self.similarity_threshold
        }


# Test functions
if __name__ == '__main__':
    print("Testing SSID Fingerprinting...")
    print()

    # Test Jaccard similarity
    print("1. Testing Jaccard Similarity:")
    pool_a = {"HomeWiFi", "WorkNet", "Starbucks", "Airport"}
    pool_b = {"HomeWiFi", "WorkNet", "Starbucks", "CoffeeShop"}
    similarity = calculate_jaccard_similarity(pool_a, pool_b)
    print(f"   Pool A: {pool_a}")
    print(f"   Pool B: {pool_b}")
    print(f"   Similarity: {similarity * 100:.1f}%")
    print()

    # Test fingerprint generation
    print("2. Testing Fingerprint Generation:")
    fp_id = generate_fingerprint_id(pool_a)
    print(f"   Fingerprint ID: {fp_id}")
    print()

    # Test SSIDPool
    print("3. Testing SSID Pool:")
    pool = SSIDPool()
    pool.add_ssid("HomeWiFi")
    pool.add_ssid("WorkNet")
    pool.add_ssid("HomeWiFi")  # Duplicate
    print(f"   Pool size: {pool.size()}")
    print(f"   SSIDs: {pool.get_ssids()}")
    print(f"   Top SSIDs: {pool.get_top_ssids()}")
    print()

    # Test FingerprintMatcher
    print("4. Testing Fingerprint Matcher:")
    matcher = FingerprintMatcher()

    # Create first fingerprint
    fp1 = matcher.create_fingerprint(pool_a, "aa:bb:cc:dd:ee:01")
    print(f"   Created fingerprint: {fp1.fingerprint_id}")

    # Try to match similar pool
    match = matcher.find_matching_fingerprint(pool_b)
    if match:
        print(f"   Match found: {match[0]} ({match[1] * 100:.1f}% similarity)")
    else:
        print("   No match found")

    print()
    print("Fingerprinting tests complete!")
