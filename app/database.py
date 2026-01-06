"""
WiFi Desk Plumbus - Database Module

This module handles SQLite database operations for the Plumbus Sentinel system.

Database Schema:
- devices: Device fingerprints and metadata
- locations: Location fingerprints and visit history
- network_observations: WiFi network scans
- probe_requests: Captured probe requests
- alerts: Following device alerts
"""

import sqlite3
import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Any
from contextlib import contextmanager

import config

logger = logging.getLogger(__name__)


class PlumbusDatabase:
    """SQLite database manager for the Plumbus Sentinel system."""

    def __init__(self, db_path: Optional[Path] = None):
        """
        Initialize database connection.

        Args:
            db_path: Path to SQLite database file (default: from config)
        """
        self.db_path = db_path or config.DATABASE_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        logger.info(f"Database initialized at: {self.db_path}")

    @contextmanager
    def get_connection(self):
        """
        Context manager for database connections.

        Yields:
            sqlite3.Connection: Database connection
        """
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row  # Enable column access by name
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            logger.error(f"Database error: {e}", exc_info=True)
            raise
        finally:
            conn.close()

    def init_schema(self):
        """Initialize database schema with all required tables."""
        logger.info("Initializing database schema...")

        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Devices table - stores device fingerprints
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS devices (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    fingerprint_id TEXT UNIQUE NOT NULL,
                    custom_name TEXT,
                    status TEXT DEFAULT 'neutral',
                    confidence REAL,
                    first_seen INTEGER NOT NULL,
                    last_seen INTEGER NOT NULL,
                    ssid_pool TEXT,
                    mac_addresses TEXT,
                    movement_correlation REAL DEFAULT 0.0,
                    notes TEXT,
                    created_at INTEGER DEFAULT (strftime('%s', 'now'))
                )
            """)

            # Locations table - stores location fingerprints
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS locations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    location_id TEXT UNIQUE NOT NULL,
                    name TEXT,
                    category TEXT DEFAULT 'other',
                    notes TEXT,
                    first_seen INTEGER NOT NULL,
                    last_seen INTEGER,
                    network_fingerprint TEXT,
                    total_visits INTEGER DEFAULT 1,
                    total_time_spent INTEGER DEFAULT 0,
                    created_at INTEGER DEFAULT (strftime('%s', 'now'))
                )
            """)

            # Network observations table - stores WiFi network scans
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS network_observations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ssid TEXT,
                    bssid TEXT NOT NULL,
                    channel INTEGER,
                    frequency_band TEXT,
                    rssi INTEGER,
                    encryption TEXT,
                    location_id TEXT,
                    timestamp INTEGER NOT NULL,
                    FOREIGN KEY (location_id) REFERENCES locations(location_id)
                )
            """)

            # Probe requests table - stores captured probe requests
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS probe_requests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    mac_address TEXT NOT NULL,
                    ssid TEXT,
                    frequency_band TEXT,
                    timestamp INTEGER NOT NULL,
                    device_fingerprint_id TEXT,
                    FOREIGN KEY (device_fingerprint_id) REFERENCES devices(fingerprint_id)
                )
            """)

            # Alerts table - stores surveillance detection alerts
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_type TEXT NOT NULL,
                    device_fingerprint_id TEXT,
                    severity TEXT NOT NULL,
                    message TEXT NOT NULL,
                    status TEXT DEFAULT 'active',
                    created_at INTEGER DEFAULT (strftime('%s', 'now')),
                    resolved_at INTEGER,
                    FOREIGN KEY (device_fingerprint_id) REFERENCES devices(fingerprint_id)
                )
            """)

            # Create indexes for better query performance
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_devices_fingerprint
                ON devices(fingerprint_id)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_devices_status
                ON devices(status)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_network_obs_timestamp
                ON network_observations(timestamp)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_network_obs_location
                ON network_observations(location_id)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_probe_requests_timestamp
                ON probe_requests(timestamp)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_probe_requests_mac
                ON probe_requests(mac_address)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_alerts_status
                ON alerts(status)
            """)

            conn.commit()
            logger.info("Database schema initialized successfully")

    # ==========================================
    # Device Operations
    # ==========================================

    def add_device(self, fingerprint_id: str, ssid_pool: List[str],
                   mac_address: str, timestamp: int) -> int:
        """
        Add a new device fingerprint to the database.

        Args:
            fingerprint_id: Unique device fingerprint identifier
            ssid_pool: List of SSIDs in device's probe pool
            mac_address: MAC address observed
            timestamp: Unix timestamp of first observation

        Returns:
            int: Device ID
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                INSERT INTO devices (
                    fingerprint_id, first_seen, last_seen,
                    ssid_pool, mac_addresses, status
                )
                VALUES (?, ?, ?, ?, ?, 'neutral')
            """, (
                fingerprint_id,
                timestamp,
                timestamp,
                json.dumps(ssid_pool),
                json.dumps([mac_address])
            ))

            device_id = cursor.lastrowid
            logger.info(f"Added device fingerprint: {fingerprint_id}")
            return device_id

    def update_device(self, fingerprint_id: str, **kwargs):
        """
        Update device information.

        Args:
            fingerprint_id: Device fingerprint ID
            **kwargs: Fields to update (custom_name, status, notes, etc.)
        """
        if not kwargs:
            return

        # Build dynamic UPDATE query
        fields = ', '.join(f"{key} = ?" for key in kwargs.keys())
        values = list(kwargs.values()) + [fingerprint_id]

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f"""
                UPDATE devices
                SET {fields}
                WHERE fingerprint_id = ?
            """, values)

            logger.info(f"Updated device {fingerprint_id}: {kwargs}")

    def get_device(self, fingerprint_id: str) -> Optional[Dict[str, Any]]:
        """
        Get device by fingerprint ID.

        Args:
            fingerprint_id: Device fingerprint ID

        Returns:
            Dict with device data or None
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM devices WHERE fingerprint_id = ?
            """, (fingerprint_id,))

            row = cursor.fetchone()
            if row:
                return dict(row)
            return None

    def get_all_devices(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get all devices, optionally filtered by status.

        Args:
            status: Filter by status (known, neutral, suspicious)

        Returns:
            List of device dictionaries
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()

            if status:
                cursor.execute("""
                    SELECT * FROM devices WHERE status = ?
                    ORDER BY last_seen DESC
                """, (status,))
            else:
                cursor.execute("""
                    SELECT * FROM devices ORDER BY last_seen DESC
                """)

            return [dict(row) for row in cursor.fetchall()]

    # ==========================================
    # Network Observation Operations
    # ==========================================

    def add_network_observation(self, ssid: str, bssid: str, channel: int,
                                frequency_band: str, rssi: int, encryption: str,
                                timestamp: int, location_id: Optional[str] = None):
        """
        Add a network observation from scanning.

        Args:
            ssid: Network SSID
            bssid: Network BSSID (MAC address)
            channel: WiFi channel
            frequency_band: '2.4GHz' or '5GHz'
            rssi: Signal strength in dBm
            encryption: Encryption type (WPA2, WPA3, etc.)
            timestamp: Unix timestamp
            location_id: Associated location ID
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                INSERT INTO network_observations (
                    ssid, bssid, channel, frequency_band, rssi,
                    encryption, location_id, timestamp
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (ssid, bssid, channel, frequency_band, rssi,
                  encryption, location_id, timestamp))

    def get_recent_networks(self, minutes: int = 5) -> List[Dict[str, Any]]:
        """
        Get networks observed in the last N minutes.

        Args:
            minutes: Time window in minutes

        Returns:
            List of network observation dictionaries
        """
        cutoff_time = int(datetime.now().timestamp()) - (minutes * 60)

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM network_observations
                WHERE timestamp > ?
                ORDER BY timestamp DESC
            """, (cutoff_time,))

            return [dict(row) for row in cursor.fetchall()]

    # ==========================================
    # Probe Request Operations
    # ==========================================

    def add_probe_request(self, mac_address: str, ssid: str,
                         frequency_band: str, timestamp: int,
                         device_fingerprint_id: Optional[str] = None):
        """
        Add a captured probe request.

        Args:
            mac_address: Device MAC address
            ssid: Probed SSID
            frequency_band: '2.4GHz' or '5GHz'
            timestamp: Unix timestamp
            device_fingerprint_id: Associated device fingerprint (if matched)
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                INSERT INTO probe_requests (
                    mac_address, ssid, frequency_band,
                    timestamp, device_fingerprint_id
                )
                VALUES (?, ?, ?, ?, ?)
            """, (mac_address, ssid, frequency_band, timestamp, device_fingerprint_id))

    def get_probe_requests_by_mac(self, mac_address: str,
                                  limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get probe requests by MAC address.

        Args:
            mac_address: Device MAC address
            limit: Maximum number of results

        Returns:
            List of probe request dictionaries
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM probe_requests
                WHERE mac_address = ?
                ORDER BY timestamp DESC
                LIMIT ?
            """, (mac_address, limit))

            return [dict(row) for row in cursor.fetchall()]

    # ==========================================
    # Alert Operations
    # ==========================================

    def add_alert(self, alert_type: str, message: str, severity: str,
                 device_fingerprint_id: Optional[str] = None):
        """
        Add a new alert.

        Args:
            alert_type: Type of alert (following_detected, etc.)
            message: Alert message
            severity: info, warning, or critical
            device_fingerprint_id: Associated device (if applicable)
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                INSERT INTO alerts (
                    alert_type, message, severity, device_fingerprint_id
                )
                VALUES (?, ?, ?, ?)
            """, (alert_type, message, severity, device_fingerprint_id))

            logger.warning(f"Alert created: {alert_type} - {message}")

    def get_active_alerts(self) -> List[Dict[str, Any]]:
        """Get all active (unresolved) alerts."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM alerts
                WHERE status = 'active'
                ORDER BY created_at DESC
            """)

            return [dict(row) for row in cursor.fetchall()]

    # ==========================================
    # Maintenance Operations
    # ==========================================

    def cleanup_old_data(self, days: int = None):
        """
        Remove data older than specified days.

        Args:
            days: Number of days to keep (default: from config)
        """
        days = days or config.DATA_RETENTION_DAYS
        cutoff_time = int(datetime.now().timestamp()) - (days * 24 * 60 * 60)

        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Delete old network observations
            cursor.execute("""
                DELETE FROM network_observations WHERE timestamp < ?
            """, (cutoff_time,))
            net_deleted = cursor.rowcount

            # Delete old probe requests
            cursor.execute("""
                DELETE FROM probe_requests WHERE timestamp < ?
            """, (cutoff_time,))
            probe_deleted = cursor.rowcount

            logger.info(f"Cleanup: Removed {net_deleted} network observations, "
                       f"{probe_deleted} probe requests older than {days} days")

    def get_database_stats(self) -> Dict[str, Any]:
        """Get database statistics."""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            stats = {}

            # Count records in each table
            for table in ['devices', 'locations', 'network_observations',
                         'probe_requests', 'alerts']:
                cursor.execute(f"SELECT COUNT(*) FROM {table}")
                stats[f"{table}_count"] = cursor.fetchone()[0]

            # Database file size
            if self.db_path.exists():
                stats['database_size_mb'] = self.db_path.stat().st_size / (1024 * 1024)
            else:
                stats['database_size_mb'] = 0

            return stats


# ==========================================
# Convenience Functions
# ==========================================

def init_db(db_path: Optional[Path] = None):
    """
    Initialize the database (convenience function).

    Args:
        db_path: Path to database file (default: from config)
    """
    db = PlumbusDatabase(db_path)
    db.init_schema()
    logger.info("Plumbus Registry initialized - Everyone has one!")
    return db


def get_db() -> PlumbusDatabase:
    """Get database instance (convenience function)."""
    return PlumbusDatabase()


if __name__ == '__main__':
    # Test database initialization
    print("Testing Plumbus Database...")
    db = init_db()
    stats = db.get_database_stats()
    print(f"Database initialized successfully!")
    print(f"Statistics: {stats}")
