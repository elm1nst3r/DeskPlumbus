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


def print_phase1_banner():
    """Print the Phase 1 banner."""
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
    ║           PHASE 1: Core WiFi Monitoring Active           ║
    ║      Plumbus Sentinel initialized... Everyone has one!   ║
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


def start_flask_server():
    """Start the Flask web server."""
    try:
        from app.api import create_app

        logger.info("Creating Flask application...")
        app = create_app()

        logger.info("=" * 60)
        logger.info("PHASE 1: WiFi Desk Plumbus Ready!")
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
        logger.info("Press Ctrl+C to stop the Plumbus")
        logger.info("=" * 60)
        logger.info("")

        # Run Flask server
        app.run(
            host=config.FLASK_HOST,
            port=config.FLASK_PORT,
            debug=config.DEBUG
        )

    except KeyboardInterrupt:
        logger.info("\nPlumbus shutdown requested by user")
    except Exception as e:
        logger.error(f"Error running Flask server: {e}", exc_info=True)
        return False

    return True


def main():
    """Main entry point for Phase 1."""
    print_phase1_banner()

    logger.info("Starting WiFi Desk Plumbus - Phase 1")
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

    # Print configuration summary
    logger.info("=" * 60)
    logger.info("CONFIGURATION SUMMARY")
    logger.info("=" * 60)
    logger.info(f"WiFi Interface: {config.WIFI_INTERFACE}")
    logger.info(f"Scan Interval: {config.SCAN_INTERVAL} seconds")
    logger.info(f"Similarity Threshold: {config.SIMILARITY_THRESHOLD * 100}%")
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
    logger.info("Phase 1 includes database and web interface.")
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
