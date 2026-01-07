#!/usr/bin/env python3
"""
WiFi Desk Plumbus - Application Entry Point

This is the main entry point for the Plumbus Sentinel system.
Run with: python3 run.py (or sudo python3 run.py for monitor mode)

Phase 1: Core WiFi Monitoring
- Database initialization
- WiFi monitor setup (requires sudo on Raspberry Pi)
- Flask web server
"""

import sys
import os
import logging
from pathlib import Path

# Add project root to Python path
PROJECT_ROOT = Path(__file__).parent.absolute()
sys.path.insert(0, str(PROJECT_ROOT))

# Import configuration
try:
    import config
except ImportError as e:
    print(f"ERROR: Could not import config: {e}")
    sys.exit(1)

# Setup logging
logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL),
    format=config.LOG_FORMAT,
    datefmt=config.LOG_DATE_FORMAT,
    handlers=[
        logging.FileHandler(config.LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)


def print_phase5_banner():
    """Print the Phase 5 banner."""
    banner = """
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║    ██████╗ ██╗     ██╗   ██╗███╗   ███╗██████╗ ██╗   ██╗ ║
    ║    ██╔══██╗██║     ██║   ██║████╗ ████║██╔══██╗██║   ██║ ║
    ║    ██████╔╝██║     ██║   ██║██╔████╔██║██████╔╝██║   ██║ ║
    ║    ██╔═══╝ ██║     ██║   ██║██║╚██╔╝██║██╔══██╗██║   ██║ ║
    ║    ██║     ███████╗╚██████╔╝██║ ╚═╝ ██║██████╔╝╚██████╔╝ ║
    ║    ╚═╝     ╚══════╝ ╚═════╝ ╚═╝     ╚═╝╚═════╝  ╚═════╝  ║
    ║                                                           ║
    ║       PHASE 5: Real-time Analytics Active!               ║
    ║      Plumbus Sentinel initialized... Everyone has one!   ║
    ║    🛸 Live updates & advanced charts! 🛸                  ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝
    """
    print(banner)


def check_requirements():
    """Check if all requirements are met."""
    logger.info("Checking requirements...")

    # Check Python version
    if sys.version_info < (3, 11):
        logger.warning(f"Python 3.11+ recommended, found {sys.version_info.major}.{sys.version_info.minor}")
    else:
        logger.info(f"Python version: {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")

    # Check required directories
    required_dirs = [config.DATA_DIR, config.LOGS_DIR]
    for directory in required_dirs:
        if not directory.exists():
            logger.info(f"Creating directory: {directory}")
            directory.mkdir(parents=True, exist_ok=True)
        else:
            logger.info(f"Directory exists: {directory}")

    # Test imports
    logger.info("Testing required Python modules...")
    required_modules = {
        'flask': 'Flask',
        'numpy': 'NumPy',
        'pandas': 'Pandas'
    }

    optional_modules = {
        'psutil': 'psutil'
    }

    missing_modules = []
    for module_name, display_name in required_modules.items():
        try:
            __import__(module_name)
            logger.info(f"  ✓ {display_name}")
        except ImportError:
            logger.error(f"  ✗ {display_name} - NOT INSTALLED")
            missing_modules.append(module_name)

    for module_name, display_name in optional_modules.items():
        try:
            __import__(module_name)
            logger.info(f"  ✓ {display_name} (optional)")
        except ImportError:
            logger.warning(f"  ○ {display_name} - Not installed (optional)")

    if missing_modules:
        logger.error("Missing required modules. Install with:")
        logger.error("  pip install -r requirements.txt")
        return False

    logger.info("All requirements met!")
    return True


def init_database():
    """Initialize the database."""
    try:
        from app.database import init_db

        logger.info("Initializing Plumbus Registry (database)...")
        db = init_db()

        stats = db.get_database_stats()
        logger.info(f"Database initialized: {stats}")

        return True

    except Exception as e:
        logger.error(f"Failed to initialize database: {e}", exc_info=True)
        return False


def init_fingerprinting():
    """Initialize Phase 2 fingerprinting system."""
    try:
        from app.fingerprint_manager import init_fingerprint_manager

        logger.info("Initializing SSID Fingerprinting (Phase 2)...")
        manager = init_fingerprint_manager()

        stats = manager.get_statistics()
        logger.info(f"Fingerprinting initialized: {stats['total_fingerprints']} fingerprints loaded")
        logger.info(f"Jaccard similarity threshold: {stats['similarity_threshold'] * 100}%")
        logger.info("🛸 Plumbus can now detect MAC randomization!")

        return manager

    except Exception as e:
        logger.error(f"Failed to initialize fingerprinting: {e}", exc_info=True)
        return None


def init_location_detection(fingerprint_manager):
    """Initialize Phase 3 location detection system."""
    try:
        from app.location import init_location_detector

        logger.info("Initializing Location Detection (Phase 3)...")
        detector = init_location_detector()

        # Connect to fingerprint manager
        if fingerprint_manager:
            fingerprint_manager.set_location_detector(detector)
            logger.info("Location detector connected to fingerprint manager")

        stats = detector.get_statistics()
        logger.info(f"Location detection initialized: {stats['total_locations']} locations loaded")
        logger.info(f"Location similarity threshold: {stats['similarity_threshold'] * 100}%")
        logger.info("🛸 Plumbus can now track physical locations!")

        return detector

    except Exception as e:
        logger.error(f"Failed to initialize location detection: {e}", exc_info=True)
        return None


def init_following_detection(fingerprint_manager):
    """Initialize Phase 4 following device detection system."""
    try:
        from app.following import init_following_detector

        logger.info("Initializing Following Detection (Phase 4)...")
        detector = init_following_detector()

        # Connect to fingerprint manager
        if fingerprint_manager:
            fingerprint_manager.set_following_detector(detector)
            logger.info("Following detector connected to fingerprint manager")

        stats = detector.get_statistics()
        logger.info(f"Following detection initialized: {stats['whitelisted_devices']} whitelisted devices")
        logger.info(f"Correlation threshold: {stats['correlation_threshold'] * 100}%")
        logger.info(f"Time window: {stats['time_window_hours']} hours")
        logger.info("🛸 Plumbus can now detect following devices!")

        return detector

    except Exception as e:
        logger.error(f"Failed to initialize following detection: {e}", exc_info=True)
        return None


def start_flask_server():
    """Start the Flask-SocketIO web server (Phase 5)."""
    try:
        from app.api import create_socketio_app

        logger.info("Creating Flask-SocketIO application...")
        app, socketio = create_socketio_app()

        logger.info("=" * 60)
        logger.info("PHASE 5: WiFi Desk Plumbus Ready!")
        logger.info("=" * 60)
        logger.info("")
        logger.info("Web Interface:")
        logger.info(f"  Local:   http://localhost:{config.FLASK_PORT}")
        logger.info(f"  Network: http://raspberrypi.local:{config.FLASK_PORT}")
        logger.info(f"  Network: http://[YOUR_PI_IP]:{config.FLASK_PORT}")
        logger.info("")
        logger.info("API Endpoints:")
        logger.info(f"  Status:  http://localhost:{config.FLASK_PORT}/api/status")
        logger.info(f"  Devices: http://localhost:{config.FLASK_PORT}/api/devices")
        logger.info(f"  Health:  http://localhost:{config.FLASK_PORT}/health")
        logger.info("")
        logger.info("WebSocket Features (Phase 5):")
        logger.info(f"  Real-time updates enabled")
        logger.info(f"  Update interval: {config.WEBSOCKET_UPDATE_INTERVAL}s")
        logger.info("")
        logger.info("Press Ctrl+C to stop the Plumbus")
        logger.info("=" * 60)
        logger.info("")

        # Run Flask-SocketIO server
        socketio.run(
            app,
            host=config.FLASK_HOST,
            port=config.FLASK_PORT,
            debug=config.DEBUG,
            allow_unsafe_werkzeug=True  # For development only
        )

    except KeyboardInterrupt:
        logger.info("\nPlumbus shutdown requested by user")
    except Exception as e:
        logger.error(f"Error running Flask-SocketIO server: {e}", exc_info=True)
        return False

    return True


def main():
    """Main entry point for Phase 5."""
    print_phase5_banner()

    logger.info("Starting WiFi Desk Plumbus - Phase 5")
    logger.info(f"Version: {config.APP_VERSION}")
    logger.info(f"Project directory: {PROJECT_ROOT}")

    # Check requirements
    if not check_requirements():
        logger.error("Requirements check failed!")
        sys.exit(1)

    # Initialize database
    if not init_database():
        logger.error("Database initialization failed!")
        sys.exit(1)

    # Initialize fingerprinting (Phase 2)
    fingerprint_manager = init_fingerprinting()
    if not fingerprint_manager:
        logger.warning("Fingerprinting initialization failed - continuing without Phase 2 features")

    # Initialize location detection (Phase 3)
    location_detector = init_location_detection(fingerprint_manager)
    if not location_detector:
        logger.warning("Location detection initialization failed - continuing without Phase 3 features")

    # Initialize following detection (Phase 4)
    following_detector = init_following_detection(fingerprint_manager)
    if not following_detector:
        logger.warning("Following detection initialization failed - continuing without Phase 4 features")

    # Print configuration summary
    logger.info("=" * 60)
    logger.info("CONFIGURATION SUMMARY")
    logger.info("=" * 60)
    logger.info(f"Phase: 5 (Real-time Analytics)")
    logger.info(f"WiFi Interface: {config.WIFI_INTERFACE}")
    logger.info(f"Scan Interval: {config.SCAN_INTERVAL} seconds")
    logger.info(f"Device Similarity Threshold: {config.SIMILARITY_THRESHOLD * 100}%")
    logger.info(f"Location Similarity Threshold: {config.LOCATION_SIMILARITY_THRESHOLD * 100}%")
    logger.info(f"Following Correlation Threshold: {config.FOLLOWING_CORRELATION_THRESHOLD * 100}%")
    logger.info(f"Min SSIDs for Fingerprint: {config.MIN_SSIDS_FOR_FINGERPRINT}")
    logger.info(f"Min BSSIDs for Location: {config.MIN_BSSIDS_FOR_LOCATION}")
    logger.info(f"Min Locations for Following Alert: {config.MIN_LOCATIONS_FOR_FOLLOWING}")
    logger.info(f"Following Time Window: {config.FOLLOWING_TIME_WINDOW_HOURS} hours")
    logger.info(f"Data Retention: {config.DATA_RETENTION_DAYS} days")
    logger.info(f"Flask Port: {config.FLASK_PORT}")
    logger.info(f"Debug Mode: {config.DEBUG}")
    logger.info(f"Database: {config.DATABASE_PATH}")
    logger.info(f"Logs: {config.LOG_FILE}")
    logger.info("=" * 60)
    logger.info("")

    # Note about WiFi monitoring
    logger.info("NOTE: WiFi monitoring requires:")
    logger.info("  - sudo privileges")
    logger.info("  - Monitor mode support (Raspberry Pi)")
    logger.info("  - Scapy library")
    logger.info("")
    logger.info("Phase 5 includes real-time updates and analytics!")
    logger.info("  - Phase 2: SSID fingerprinting defeats MAC randomization")
    logger.info("  - Phase 3: Location tracking via visible WiFi networks")
    logger.info("  - Phase 4: Detect devices following you across locations")
    logger.info("  - Phase 5: Real-time WebSocket updates & advanced charts")
    logger.info("Active WiFi monitoring will be enabled when running on Raspberry Pi with sudo.")
    logger.info("")

    # Start Flask server
    start_flask_server()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        logger.info("\nPlumbus shutdown requested by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)
