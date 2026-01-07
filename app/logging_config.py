"""
WiFi Desk Plumbus - Logging Configuration Module

Centralized logging configuration with rotation support (Phase 6).

Features:
- Log rotation by size
- Configurable retention
- Console and file outputs
- Structured log format
"""

import logging
import logging.handlers
import os
from pathlib import Path
import config


def setup_logging():
    """
    Configure logging for the entire application.

    Sets up:
    - Rotating file handler (10MB max, 5 backups)
    - Console handler for stdout
    - Consistent formatting
    - Configurable log level
    """
    # Create logs directory if it doesn't exist
    config.LOGS_DIR.mkdir(parents=True, exist_ok=True)

    # Get log level from config
    log_level_str = getattr(config, 'LOG_LEVEL', 'INFO')
    log_level = getattr(logging, log_level_str, logging.INFO)

    # Log file path
    log_file = config.LOGS_DIR / 'plumbus.log'

    # Get rotation settings from config
    max_bytes = getattr(config, 'LOG_MAX_SIZE_MB', 10) * 1024 * 1024  # Convert MB to bytes
    backup_count = getattr(config, 'LOG_BACKUP_COUNT', 5)

    # Create formatters
    detailed_formatter = logging.Formatter(
        fmt='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    console_formatter = logging.Formatter(
        fmt='[%(levelname)s] %(name)s: %(message)s'
    )

    # Create rotating file handler
    file_handler = logging.handlers.RotatingFileHandler(
        filename=log_file,
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding='utf-8'
    )
    file_handler.setLevel(log_level)
    file_handler.setFormatter(detailed_formatter)

    # Create console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    console_handler.setFormatter(console_formatter)

    # Get root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # Remove any existing handlers
    root_logger.handlers.clear()

    # Add handlers to root logger
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)

    # Log initial message
    logging.info("=" * 60)
    logging.info("WiFi Desk Plumbus - Logging System Initialized")
    logging.info(f"Log Level: {log_level_str}")
    logging.info(f"Log File: {log_file}")
    logging.info(f"Max Size: {max_bytes / (1024 * 1024):.1f} MB")
    logging.info(f"Backup Count: {backup_count}")
    logging.info("=" * 60)

    # Suppress noisy third-party loggers
    logging.getLogger('werkzeug').setLevel(logging.WARNING)
    logging.getLogger('engineio').setLevel(logging.WARNING)
    logging.getLogger('socketio').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)

    return root_logger


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance with the given name.

    Args:
        name: Logger name (usually __name__)

    Returns:
        Logger instance
    """
    return logging.getLogger(name)


class LoggerMixin:
    """
    Mixin class to add logging capability to any class.

    Usage:
        class MyClass(LoggerMixin):
            def some_method(self):
                self.logger.info("Hello from MyClass")
    """

    @property
    def logger(self) -> logging.Logger:
        """Get logger for this class."""
        name = f"{self.__class__.__module__}.{self.__class__.__name__}"
        return logging.getLogger(name)


# Test logging module
if __name__ == '__main__':
    print("Testing Logging Configuration...")

    # Setup logging
    setup_logging()

    # Create test logger
    test_logger = get_logger(__name__)

    # Test different log levels
    test_logger.debug("This is a DEBUG message")
    test_logger.info("This is an INFO message")
    test_logger.warning("This is a WARNING message")
    test_logger.error("This is an ERROR message")
    test_logger.critical("This is a CRITICAL message")

    # Test exception logging
    try:
        1 / 0
    except Exception as e:
        test_logger.exception("Exception caught during division")

    print(f"\nLog file created at: {config.LOGS_DIR / 'plumbus.log'}")
    print("Logging configuration test complete!")
