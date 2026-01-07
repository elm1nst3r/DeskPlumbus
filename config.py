"""
WiFi Desk Plumbus - Configuration Module

Centralized configuration for the Plumbus Sentinel system.
Adjust these settings to customize your Plumbus behavior.
"""

import os
from pathlib import Path

# ===========================
# Base Paths
# ===========================

# Project root directory
BASE_DIR = Path(__file__).parent.absolute()

# Data directory (databases, exports, etc.)
DATA_DIR = BASE_DIR / 'data'

# Logs directory
LOGS_DIR = BASE_DIR / 'logs'

# Web static files
STATIC_DIR = BASE_DIR / 'web' / 'static'

# Web templates
TEMPLATES_DIR = BASE_DIR / 'web' / 'templates'

# Create directories if they don't exist
DATA_DIR.mkdir(exist_ok=True)
LOGS_DIR.mkdir(exist_ok=True)

# ===========================
# WiFi Monitor Settings
# ===========================

# WiFi interface name (usually wlan0 on Raspberry Pi)
WIFI_INTERFACE = os.getenv('WIFI_INTERFACE', 'wlan0')

# Network scan interval in seconds
SCAN_INTERVAL = int(os.getenv('SCAN_INTERVAL', 5))

# Minimum scan interval (safety limit)
MIN_SCAN_INTERVAL = 1

# Maximum scan interval
MAX_SCAN_INTERVAL = 30

# Monitor both 2.4 GHz and 5 GHz bands
MONITOR_2GHZ = True
MONITOR_5GHZ = True

# Channels to scan (empty list = all channels)
# 2.4 GHz: 1-14, 5 GHz: 36-165
SCAN_CHANNELS_2GHZ = []  # Empty = auto-scan all
SCAN_CHANNELS_5GHZ = []  # Empty = auto-scan all

# ===========================
# Fingerprinting Settings
# ===========================

# SSID pool similarity threshold (Jaccard coefficient)
# 0.85 = 85% similarity required for device match
SIMILARITY_THRESHOLD = float(os.getenv('SIMILARITY_THRESHOLD', 0.85))

# Minimum similarity (safety limit)
MIN_SIMILARITY = 0.5

# Maximum similarity
MAX_SIMILARITY = 1.0

# Maximum SSIDs to store per device fingerprint
MAX_SSIDS_PER_DEVICE = 100

# Maximum device fingerprints to store
MAX_DEVICES = 2000

# Minimum SSIDs required for reliable fingerprint
MIN_SSIDS_FOR_FINGERPRINT = 3

# ===========================
# Location Detection Settings (Phase 3)
# ===========================

# Minimum networks (BSSIDs) required for location fingerprint
MIN_NETWORKS_FOR_LOCATION = 3
MIN_BSSIDS_FOR_LOCATION = MIN_NETWORKS_FOR_LOCATION  # Alias for clarity

# Location similarity threshold (Jaccard coefficient)
# 0.60 = 60% similarity required for location match (lower than device matching
# because WiFi environments can vary more over time as APs come and go)
LOCATION_SIMILARITY_THRESHOLD = 0.60

# Location confidence threshold (percentage) - deprecated, use LOCATION_SIMILARITY_THRESHOLD
LOCATION_CONFIDENCE_THRESHOLD = LOCATION_SIMILARITY_THRESHOLD * 100

# Maximum locations to track
MAX_LOCATIONS = 500

# Location categories
LOCATION_CATEGORIES = [
    'home',
    'work',
    'public',
    'travel',
    'other'
]

# ===========================
# Following Device Detection (Phase 4)
# ===========================

# Correlation score threshold for following alert (0.0 to 1.0)
# 0.5 = 50% correlation required to trigger alert
FOLLOWING_CORRELATION_THRESHOLD = float(os.getenv('FOLLOWING_CORRELATION_THRESHOLD', 0.5))

# Time window for following detection (hours)
# Only consider device appearances within this window
FOLLOWING_TIME_WINDOW_HOURS = int(os.getenv('FOLLOWING_TIME_WINDOW_HOURS', 24))

# Minimum number of location overlaps before alerting
# Device must appear at this many of your locations to be suspicious
MIN_LOCATIONS_FOR_FOLLOWING = int(os.getenv('MIN_LOCATIONS_FOR_FOLLOWING', 2))

# Number of locations before triggering alert (legacy)
ALERT_LOCATION_COUNT = int(os.getenv('ALERT_LOCATION_COUNT', 3))

# Time window for correlation (seconds) (legacy)
# 1800 = 30 minutes
ALERT_TIME_WINDOW = int(os.getenv('ALERT_TIME_WINDOW', 1800))

# Device status types
DEVICE_STATUS_KNOWN = 'known'
DEVICE_STATUS_NEUTRAL = 'neutral'
DEVICE_STATUS_SUSPICIOUS = 'suspicious'

# Alert severity levels
ALERT_SEVERITY_INFO = 'info'
ALERT_SEVERITY_WARNING = 'warning'
ALERT_SEVERITY_CRITICAL = 'critical'

# ===========================
# Database Settings
# ===========================

# SQLite database path
DATABASE_PATH = DATA_DIR / 'tracker.db'

# Database backup path
DATABASE_BACKUP_PATH = DATA_DIR / 'backups'

# Auto-backup interval (hours)
BACKUP_INTERVAL_HOURS = 24

# Data retention period (days)
DATA_RETENTION_DAYS = int(os.getenv('DATA_RETENTION_DAYS', 90))

# Auto-cleanup enabled
AUTO_CLEANUP = True

# ===========================
# Flask Settings
# ===========================

# Flask secret key (change in production!)
SECRET_KEY = os.getenv('SECRET_KEY', 'plumbus-secret-key-change-me')

# Flask debug mode (disable in production)
DEBUG = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'

# Flask host (0.0.0.0 = accessible from network)
FLASK_HOST = os.getenv('FLASK_HOST', '0.0.0.0')

# Flask port
FLASK_PORT = int(os.getenv('FLASK_PORT', 5000))

# Enable Flask development mode
ENV = 'development' if DEBUG else 'production'

# ===========================
# WebSocket Settings
# ===========================

# WebSocket update interval (seconds)
WEBSOCKET_UPDATE_INTERVAL = int(os.getenv('WEBSOCKET_UPDATE_INTERVAL', 2))

# WebSocket async mode (eventlet for production)
SOCKETIO_ASYNC_MODE = 'eventlet'

# WebSocket message queue
SOCKETIO_MESSAGE_QUEUE = None

# CORS settings for WebSocket
SOCKETIO_CORS_ALLOWED_ORIGINS = '*'

# ===========================
# Logging Settings
# ===========================

# Log file path
LOG_FILE = LOGS_DIR / 'plumbus.log'

# Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')

# Log format
LOG_FORMAT = '%(asctime)s [%(levelname)s] %(name)s: %(message)s'

# Log date format
LOG_DATE_FORMAT = '%Y-%m-%d %H:%M:%S'

# Max log file size (bytes) - 10 MB
LOG_MAX_BYTES = 10 * 1024 * 1024

# Number of backup log files to keep
LOG_BACKUP_COUNT = 5

# ===========================
# Security Settings
# ===========================

# Enable password protection (requires Flask-Login)
PASSWORD_PROTECTION_ENABLED = False

# Default admin username
ADMIN_USERNAME = os.getenv('ADMIN_USERNAME', 'admin')

# Default admin password (change immediately!)
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'plumbus')

# Session timeout (minutes)
SESSION_TIMEOUT = 60

# Enable HTTPS (requires SSL certificates)
HTTPS_ENABLED = False

# SSL certificate paths
SSL_CERT_PATH = None
SSL_KEY_PATH = None

# ===========================
# Performance Settings
# ===========================

# Enable packet capture threading
THREADED_CAPTURE = True

# Packet capture queue size
CAPTURE_QUEUE_SIZE = 1000

# Database connection pool size
DB_POOL_SIZE = 5

# Enable query result caching
ENABLE_CACHING = True

# Cache timeout (seconds)
CACHE_TIMEOUT = 300

# ===========================
# UI Settings
# ===========================

# Items per page in device list
ITEMS_PER_PAGE = 50

# Chart data points limit
CHART_MAX_POINTS = 100

# Refresh intervals (milliseconds)
UI_REFRESH_INTERVAL = 5000

# Date format for UI
UI_DATE_FORMAT = '%Y-%m-%d %H:%M:%S'

# ===========================
# Export Settings
# ===========================

# Export directory
EXPORT_DIR = DATA_DIR / 'exports'

# Create export directory
EXPORT_DIR.mkdir(exist_ok=True)

# Maximum export file size (MB)
MAX_EXPORT_SIZE_MB = 50

# ===========================
# Plumbus Fun Messages
# ===========================

# Startup message
STARTUP_MESSAGE = """
    ╔═══════════════════════════════════════════════════════════╗
    ║  Plumbus Sentinel initialized... Everyone has one!        ║
    ╚═══════════════════════════════════════════════════════════╝
"""

# Alert messages
ALERT_MESSAGES = {
    'following_detected': 'Plumbus detected anomalous device behavior!',
    'location_changed': 'Plumbus transported to new location',
    'new_device': 'New Plumbus signature detected',
    'suspicious_device': 'Suspicious Plumbus activity detected!'
}

# ===========================
# Development/Testing Settings
# ===========================

# Enable test mode (uses in-memory database)
TEST_MODE = os.getenv('TEST_MODE', 'False').lower() == 'true'

# Mock data generation for testing
GENERATE_MOCK_DATA = False

# Verbose logging for debugging
VERBOSE_LOGGING = DEBUG

# ===========================
# System Information
# ===========================

# Application name
APP_NAME = 'WiFi Desk Plumbus'

# Application version
APP_VERSION = '1.0.0'

# Author
APP_AUTHOR = 'Roy (elm1nst3r)'

# GitHub repository
GITHUB_REPO = 'https://github.com/elm1nst3r/DeskPlumbus'

# Legal disclaimer
LEGAL_DISCLAIMER = """
WiFi Desk Plumbus is for PERSONAL security awareness ONLY.
Do NOT use for surveillance of others. Comply with local privacy laws.
"""

# ===========================
# Configuration Validation
# ===========================

def validate_config():
    """Validate configuration settings."""
    errors = []

    # Validate scan interval
    if not MIN_SCAN_INTERVAL <= SCAN_INTERVAL <= MAX_SCAN_INTERVAL:
        errors.append(f"SCAN_INTERVAL must be between {MIN_SCAN_INTERVAL} and {MAX_SCAN_INTERVAL}")

    # Validate similarity threshold
    if not MIN_SIMILARITY <= SIMILARITY_THRESHOLD <= MAX_SIMILARITY:
        errors.append(f"SIMILARITY_THRESHOLD must be between {MIN_SIMILARITY} and {MAX_SIMILARITY}")

    # Validate data retention
    if DATA_RETENTION_DAYS < 1:
        errors.append("DATA_RETENTION_DAYS must be at least 1")

    # Validate alert settings
    if ALERT_LOCATION_COUNT < 2:
        errors.append("ALERT_LOCATION_COUNT must be at least 2")

    if errors:
        raise ValueError("Configuration errors:\n" + "\n".join(errors))

    return True

# Validate on import
if not TEST_MODE:
    validate_config()
