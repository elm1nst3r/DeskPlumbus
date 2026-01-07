"""
WiFi Desk Plumbus - WebSocket Module

This module handles real-time WebSocket communication using Flask-SocketIO.
Provides live updates for devices, locations, alerts, and statistics.

Phase 5: Real-time Updates & Advanced Analytics
"""

import logging
import time
import threading
from typing import Optional
from datetime import datetime

import config
from app.database import get_db
from app.fingerprint_manager import get_fingerprint_manager
from app.location import get_location_detector
from app.following import get_following_detector

logger = logging.getLogger(__name__)

# Global SocketIO instance (will be set by create_socketio_app)
socketio_instance: Optional[any] = None


def set_socketio_instance(socketio):
    """Set the global SocketIO instance."""
    global socketio_instance
    socketio_instance = socketio
    logger.info("SocketIO instance registered")


def get_socketio():
    """Get the global SocketIO instance."""
    return socketio_instance


def register_socketio_events(socketio):
    """
    Register WebSocket event handlers.

    Args:
        socketio: Flask-SocketIO instance
    """

    @socketio.on('connect')
    def handle_connect():
        """Handle client connection."""
        logger.info(f"Client connected")

        # Send initial data
        emit_system_status()
        emit_statistics()
        emit_fingerprint_statistics()
        emit_location_data()
        emit_following_statistics()
        emit_recent_alerts()

        return True

    @socketio.on('disconnect')
    def handle_disconnect():
        """Handle client disconnection."""
        logger.info(f"Client disconnected")

    @socketio.on('request_update')
    def handle_request_update(data):
        """
        Handle manual update request from client.

        Args:
            data: Dict with 'type' key specifying what to update
        """
        update_type = data.get('type', 'all')

        logger.debug(f"Update requested: {update_type}")

        if update_type == 'all' or update_type == 'status':
            emit_system_status()

        if update_type == 'all' or update_type == 'statistics':
            emit_statistics()
            emit_fingerprint_statistics()
            emit_location_data()
            emit_following_statistics()

        if update_type == 'all' or update_type == 'alerts':
            emit_recent_alerts()

        if update_type == 'all' or update_type == 'devices':
            emit_device_list()


def emit_system_status():
    """Broadcast system status to all clients."""
    try:
        if not socketio_instance:
            return

        db = get_db()
        stats = db.get_database_stats()

        data = {
            'status': 'active',
            'wifi_interface': config.WIFI_INTERFACE,
            'scan_interval': config.SCAN_INTERVAL,
            'database_size_mb': stats.get('database_size_mb', 0),
            'timestamp': int(datetime.now().timestamp())
        }

        socketio_instance.emit('status_update', data)
        logger.debug("Emitted status update")

    except Exception as e:
        logger.error(f"Error emitting status: {e}", exc_info=True)


def emit_statistics():
    """Broadcast general statistics to all clients."""
    try:
        if not socketio_instance:
            return

        db = get_db()
        db_stats = db.get_database_stats()

        # Get device counts by status
        devices = db.get_all_devices()
        known_count = len([d for d in devices if d['status'] == 'known'])
        neutral_count = len([d for d in devices if d['status'] == 'neutral'])
        suspicious_count = len([d for d in devices if d['status'] == 'suspicious'])

        data = {
            'database': db_stats,
            'devices_by_status': {
                'known': known_count,
                'neutral': neutral_count,
                'suspicious': suspicious_count
            },
            'timestamp': int(datetime.now().timestamp())
        }

        socketio_instance.emit('statistics_update', data)
        logger.debug("Emitted statistics update")

    except Exception as e:
        logger.error(f"Error emitting statistics: {e}", exc_info=True)


def emit_fingerprint_statistics():
    """Broadcast fingerprinting statistics to all clients."""
    try:
        if not socketio_instance:
            return

        manager = get_fingerprint_manager()
        stats = manager.get_statistics()

        data = {
            **stats,
            'timestamp': int(datetime.now().timestamp())
        }

        socketio_instance.emit('fingerprint_stats_update', data)
        logger.debug("Emitted fingerprint statistics")

    except Exception as e:
        logger.error(f"Error emitting fingerprint stats: {e}", exc_info=True)


def emit_location_data():
    """Broadcast location data to all clients."""
    try:
        if not socketio_instance:
            return

        detector = get_location_detector()

        # Current location
        current_location = None
        if detector.current_location_id:
            location = detector.locations.get(detector.current_location_id)
            if location:
                current_location = {
                    'location_id': location.location_id,
                    'name': location.name,
                    'category': location.category,
                    'bssid_count': location.bssid_pool.size(),
                    'confidence': location.confidence
                }

        # Statistics
        stats = detector.get_statistics()

        data = {
            'current_location': current_location,
            'statistics': stats,
            'timestamp': int(datetime.now().timestamp())
        }

        socketio_instance.emit('location_update', data)
        logger.debug("Emitted location update")

    except Exception as e:
        logger.error(f"Error emitting location data: {e}", exc_info=True)


def emit_following_statistics():
    """Broadcast following detection statistics to all clients."""
    try:
        if not socketio_instance:
            return

        detector = get_following_detector()
        stats = detector.get_statistics()

        data = {
            **stats,
            'timestamp': int(datetime.now().timestamp())
        }

        socketio_instance.emit('following_stats_update', data)
        logger.debug("Emitted following statistics")

    except Exception as e:
        logger.error(f"Error emitting following stats: {e}", exc_info=True)


def emit_recent_alerts():
    """Broadcast recent alerts to all clients."""
    try:
        if not socketio_instance:
            return

        db = get_db()

        # Get recent alerts (last 24 hours)
        from datetime import timedelta
        cutoff_time = int((datetime.now() - timedelta(hours=24)).timestamp())

        try:
            all_alerts = db.get_all_alerts()
            recent_alerts = [
                alert for alert in all_alerts
                if alert.get('timestamp', 0) >= cutoff_time
            ]
        except AttributeError:
            # Database method not implemented yet
            recent_alerts = []

        data = {
            'alerts': recent_alerts,
            'count': len(recent_alerts),
            'timestamp': int(datetime.now().timestamp())
        }

        socketio_instance.emit('alerts_update', data)
        logger.debug(f"Emitted {len(recent_alerts)} recent alerts")

    except Exception as e:
        logger.error(f"Error emitting alerts: {e}", exc_info=True)


def emit_device_list():
    """Broadcast device list to all clients."""
    try:
        if not socketio_instance:
            return

        manager = get_fingerprint_manager()
        devices = manager.get_device_list()

        data = {
            'devices': devices,
            'count': len(devices),
            'timestamp': int(datetime.now().timestamp())
        }

        socketio_instance.emit('devices_update', data)
        logger.debug(f"Emitted {len(devices)} devices")

    except Exception as e:
        logger.error(f"Error emitting device list: {e}", exc_info=True)


def emit_alert_notification(alert_data: dict):
    """
    Broadcast an alert notification to all clients.

    This is called when a new alert is generated (e.g., following device detected).

    Args:
        alert_data: Alert information
    """
    try:
        if not socketio_instance:
            return

        data = {
            **alert_data,
            'timestamp': int(datetime.now().timestamp())
        }

        socketio_instance.emit('new_alert', data)
        logger.info(f"Emitted new alert notification: {alert_data.get('alert_type')}")

    except Exception as e:
        logger.error(f"Error emitting alert notification: {e}", exc_info=True)


def start_background_updates(socketio):
    """
    Start background task to periodically broadcast updates.

    Args:
        socketio: Flask-SocketIO instance
    """

    def background_task():
        """Background task that runs periodically."""
        logger.info("Background update task started")

        update_interval = config.WEBSOCKET_UPDATE_INTERVAL  # seconds

        while True:
            try:
                # Sleep first
                time.sleep(update_interval)

                # Broadcast updates (no app context needed with eventlet)
                emit_system_status()
                emit_statistics()
                emit_fingerprint_statistics()
                emit_location_data()
                emit_following_statistics()
                emit_recent_alerts()

                # Update e-ink display if available
                try:
                    if config.EINK_ENABLED:
                        from app.eink_display import get_eink_display
                        display = get_eink_display()
                        if display and display.available:
                            display.update()
                except Exception as e:
                    logger.debug(f"E-ink display update skipped: {e}")

                logger.debug(f"Background update completed (interval: {update_interval}s)")

            except Exception as e:
                logger.error(f"Error in background update task: {e}", exc_info=True)
                time.sleep(5)  # Wait before retrying

    # Start background thread
    thread = threading.Thread(target=background_task, daemon=True)
    thread.start()

    logger.info(f"Background updates started (interval: {config.WEBSOCKET_UPDATE_INTERVAL}s)")


# Test function
if __name__ == '__main__':
    print("WebSocket Module - Phase 5")
    print()
    print("This module provides real-time WebSocket communication.")
    print()
    print("Events:")
    print("  - status_update: System status")
    print("  - statistics_update: General statistics")
    print("  - fingerprint_stats_update: Fingerprinting stats")
    print("  - location_update: Location data")
    print("  - following_stats_update: Following detection stats")
    print("  - alerts_update: Recent alerts")
    print("  - devices_update: Device list")
    print("  - new_alert: Real-time alert notification")
    print()
    print("WebSocket module ready!")
