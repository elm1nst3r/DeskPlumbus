"""
WiFi Desk Plumbus - Flask API Module

This module provides RESTful API endpoints and web interface for the Plumbus Sentinel.

Phase 1 Implementation:
- Basic Flask application setup
- System status endpoint
- Network list endpoint
- Simple dashboard

Phase 5 Implementation:
- Flask-SocketIO for real-time WebSocket updates
- Background task for periodic broadcasting
"""

import logging
from datetime import datetime
from flask import Flask, jsonify, render_template, request
from flask_socketio import SocketIO
from pathlib import Path

import config
from app.database import get_db

logger = logging.getLogger(__name__)


def create_app():
    """
    Application factory for creating Flask app.

    Returns:
        Flask: Configured Flask application
    """
    app = Flask(
        __name__,
        template_folder=str(config.TEMPLATES_DIR),
        static_folder=str(config.STATIC_DIR)
    )

    # Configure Flask
    app.config['SECRET_KEY'] = config.SECRET_KEY
    app.config['DEBUG'] = config.DEBUG

    # Setup logging
    if not app.debug:
        app.logger.setLevel(logging.INFO)

    logger.info("Flask application created")

    # Register routes
    register_routes(app)

    logger.info("Flask routes registered")

    return app


def create_socketio_app():
    """
    Create Flask-SocketIO application (Phase 5).

    Returns:
        tuple: (Flask app, SocketIO instance)
    """
    # Create Flask app
    app = create_app()

    # Create SocketIO instance
    socketio = SocketIO(
        app,
        cors_allowed_origins=config.SOCKETIO_CORS_ALLOWED_ORIGINS,
        async_mode=config.SOCKETIO_ASYNC_MODE,
        logger=False,
        engineio_logger=False
    )

    # Register WebSocket events
    from app.websocket import register_socketio_events, set_socketio_instance, start_background_updates

    set_socketio_instance(socketio)
    register_socketio_events(socketio)

    # Start background update task
    start_background_updates(socketio)

    logger.info("Flask-SocketIO application created (Phase 5)")

    return app, socketio


def register_routes(app: Flask):
    """
    Register all Flask routes.

    Args:
        app: Flask application instance
    """

    # ==========================================
    # Web Interface Routes
    # ==========================================

    @app.route('/')
    def index():
        """Render main dashboard."""
        return render_template('index.html')

    @app.route('/test/websocket')
    def test_websocket():
        """Render WebSocket test page (Phase 5)."""
        return render_template('test_websocket.html')

    # ==========================================
    # API Routes
    # ==========================================

    @app.route('/api/status')
    def api_status():
        """
        Get system status.

        Returns:
            JSON with system information
        """
        try:
            db = get_db()
            db_stats = db.get_database_stats()

            status = {
                'status': 'running',
                'timestamp': int(datetime.now().timestamp()),
                'app_name': config.APP_NAME,
                'app_version': config.APP_VERSION,
                'wifi_interface': config.WIFI_INTERFACE,
                'scan_interval': config.SCAN_INTERVAL,
                'database': db_stats,
                'phase': 1,
                'phase_name': 'Core WiFi Monitoring'
            }

            return jsonify(status)

        except Exception as e:
            logger.error(f"Error getting status: {e}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    @app.route('/api/devices')
    def api_devices():
        """
        Get list of devices.

        Query params:
            status: Filter by status (known, neutral, suspicious)
            limit: Maximum number of results

        Returns:
            JSON with device list
        """
        try:
            db = get_db()

            status_filter = request.args.get('status')
            limit = request.args.get('limit', type=int, default=100)

            devices = db.get_all_devices(status=status_filter)

            # Apply limit
            if limit:
                devices = devices[:limit]

            return jsonify({
                'devices': devices,
                'count': len(devices)
            })

        except Exception as e:
            logger.error(f"Error getting devices: {e}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    @app.route('/api/devices/<fingerprint_id>')
    def api_device_detail(fingerprint_id: str):
        """
        Get device details.

        Args:
            fingerprint_id: Device fingerprint ID

        Returns:
            JSON with device details
        """
        try:
            db = get_db()
            device = db.get_device(fingerprint_id)

            if not device:
                return jsonify({'error': 'Device not found'}), 404

            return jsonify(device)

        except Exception as e:
            logger.error(f"Error getting device: {e}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    @app.route('/api/networks/recent')
    def api_recent_networks():
        """
        Get recently observed networks.

        Query params:
            minutes: Time window in minutes (default: 5)

        Returns:
            JSON with network list
        """
        try:
            db = get_db()
            minutes = request.args.get('minutes', type=int, default=5)

            networks = db.get_recent_networks(minutes=minutes)

            return jsonify({
                'networks': networks,
                'count': len(networks),
                'time_window_minutes': minutes
            })

        except Exception as e:
            logger.error(f"Error getting networks: {e}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    @app.route('/api/alerts')
    def api_alerts():
        """
        Get active alerts.

        Returns:
            JSON with alert list
        """
        try:
            db = get_db()
            alerts = db.get_active_alerts()

            return jsonify({
                'alerts': alerts,
                'count': len(alerts)
            })

        except Exception as e:
            logger.error(f"Error getting alerts: {e}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    @app.route('/api/fingerprints')
    def api_fingerprints():
        """
        Get all device fingerprints (Phase 2).

        Returns:
            JSON with fingerprint list
        """
        try:
            # Import here to avoid circular dependency
            from app.fingerprint_manager import get_fingerprint_manager

            manager = get_fingerprint_manager()
            devices = manager.get_device_list()

            return jsonify({
                'fingerprints': devices,
                'count': len(devices)
            })

        except Exception as e:
            logger.error(f"Error getting fingerprints: {e}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    @app.route('/api/fingerprints/statistics')
    def api_fingerprint_statistics():
        """
        Get fingerprinting statistics (Phase 2).

        Returns:
            JSON with fingerprinting stats
        """
        try:
            from app.fingerprint_manager import get_fingerprint_manager

            manager = get_fingerprint_manager()
            stats = manager.get_statistics()

            return jsonify(stats)

        except Exception as e:
            logger.error(f"Error getting fingerprint statistics: {e}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    @app.route('/api/locations')
    def api_locations():
        """
        Get all locations (Phase 3).

        Returns:
            JSON with location list
        """
        try:
            from app.location import get_location_detector

            detector = get_location_detector()
            locations = []

            for location_id, location in detector.locations.items():
                locations.append({
                    'location_id': location.location_id,
                    'name': location.name,
                    'bssid_count': location.bssid_pool.size(),
                    'first_detected': location.first_detected,
                    'last_detected': location.last_detected,
                    'detection_count': location.detection_count,
                    'is_current': location_id == detector.current_location_id
                })

            # Sort by last detected (most recent first)
            locations.sort(key=lambda x: x['last_detected'], reverse=True)

            return jsonify({
                'locations': locations,
                'count': len(locations)
            })

        except Exception as e:
            logger.error(f"Error getting locations: {e}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    @app.route('/api/locations/current')
    def api_current_location():
        """
        Get current location (Phase 3).

        Returns:
            JSON with current location or null
        """
        try:
            from app.location import get_location_detector

            detector = get_location_detector()
            current = detector.get_current_location()

            if current:
                return jsonify({
                    'location_id': current.location_id,
                    'name': current.name,
                    'bssid_count': current.bssid_pool.size(),
                    'first_detected': current.first_detected,
                    'last_detected': current.last_detected,
                    'detection_count': current.detection_count
                })
            else:
                return jsonify({'location': None})

        except Exception as e:
            logger.error(f"Error getting current location: {e}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    @app.route('/api/locations/statistics')
    def api_location_statistics():
        """
        Get location detection statistics (Phase 3).

        Returns:
            JSON with location stats
        """
        try:
            from app.location import get_location_detector

            detector = get_location_detector()
            stats = detector.get_statistics()

            return jsonify(stats)

        except Exception as e:
            logger.error(f"Error getting location statistics: {e}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    # ==================== Phase 4: Following Detection Endpoints ====================

    @app.route('/api/alerts/recent')
    def api_recent_alerts():
        """
        Get recent alerts (last 24 hours) (Phase 4).

        Returns:
            JSON with recent alerts
        """
        try:
            db = get_db()
            from datetime import datetime, timedelta

            # Get alerts from last 24 hours
            cutoff_time = int((datetime.now() - timedelta(hours=24)).timestamp())
            all_alerts = db.get_all_alerts()

            recent_alerts = [
                alert for alert in all_alerts
                if alert.get('timestamp', 0) >= cutoff_time
            ]

            return jsonify({
                'alerts': recent_alerts,
                'count': len(recent_alerts),
                'time_window_hours': 24
            })

        except Exception as e:
            logger.error(f"Error getting recent alerts: {e}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    @app.route('/api/following/statistics')
    def api_following_statistics():
        """
        Get following detection statistics (Phase 4).

        Returns:
            JSON with following detection stats
        """
        try:
            from app.following import get_following_detector

            detector = get_following_detector()
            stats = detector.get_statistics()

            return jsonify(stats)

        except Exception as e:
            logger.error(f"Error getting following statistics: {e}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    @app.route('/api/devices/<device_id>/whitelist', methods=['POST'])
    def api_whitelist_device(device_id):
        """
        Add device to whitelist (Phase 4).

        Args:
            device_id: Device fingerprint ID

        Returns:
            JSON with success message
        """
        try:
            from app.following import get_following_detector

            detector = get_following_detector()
            detector.add_to_whitelist(device_id)

            # Also update device status in database
            from app.fingerprint import get_fingerprint_matcher
            matcher = get_fingerprint_matcher()

            if device_id in matcher.fingerprints:
                fingerprint = matcher.fingerprints[device_id]
                fingerprint.status = 'known'
                matcher.save_fingerprint_to_database(fingerprint)

            return jsonify({
                'success': True,
                'message': f'Device {device_id[:8]} added to whitelist',
                'device_id': device_id
            })

        except Exception as e:
            logger.error(f"Error whitelisting device: {e}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    @app.route('/api/devices/<device_id>/whitelist', methods=['DELETE'])
    def api_unwhitelist_device(device_id):
        """
        Remove device from whitelist (Phase 4).

        Args:
            device_id: Device fingerprint ID

        Returns:
            JSON with success message
        """
        try:
            from app.following import get_following_detector

            detector = get_following_detector()
            detector.remove_from_whitelist(device_id)

            # Also update device status in database
            from app.fingerprint import get_fingerprint_matcher
            matcher = get_fingerprint_matcher()

            if device_id in matcher.fingerprints:
                fingerprint = matcher.fingerprints[device_id]
                fingerprint.status = 'neutral'
                matcher.save_fingerprint_to_database(fingerprint)

            return jsonify({
                'success': True,
                'message': f'Device {device_id[:8]} removed from whitelist',
                'device_id': device_id
            })

        except Exception as e:
            logger.error(f"Error removing device from whitelist: {e}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    @app.route('/api/devices/<device_id>/status', methods=['PUT'])
    def api_update_device_status(device_id):
        """
        Update device status (Phase 4).

        Args:
            device_id: Device fingerprint ID

        Request JSON:
            {
                "status": "known"|"neutral"|"suspicious"
            }

        Returns:
            JSON with success message
        """
        try:
            from flask import request
            from app.fingerprint import get_fingerprint_matcher
            from app.following import get_following_detector

            data = request.get_json()
            new_status = data.get('status', 'neutral')

            # Validate status
            valid_statuses = ['known', 'neutral', 'suspicious']
            if new_status not in valid_statuses:
                return jsonify({
                    'error': f'Invalid status. Must be one of: {", ".join(valid_statuses)}'
                }), 400

            # Update fingerprint status
            matcher = get_fingerprint_matcher()

            if device_id not in matcher.fingerprints:
                return jsonify({'error': 'Device not found'}), 404

            fingerprint = matcher.fingerprints[device_id]
            fingerprint.status = new_status
            matcher.save_fingerprint_to_database(fingerprint)

            # Update whitelist if status is 'known'
            detector = get_following_detector()
            if new_status == 'known':
                detector.add_to_whitelist(device_id)
            else:
                detector.remove_from_whitelist(device_id)

            return jsonify({
                'success': True,
                'message': f'Device {device_id[:8]} status updated to {new_status}',
                'device_id': device_id,
                'status': new_status
            })

        except Exception as e:
            logger.error(f"Error updating device status: {e}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    @app.route('/api/statistics')
    def api_statistics():
        """
        Get system statistics.

        Returns:
            JSON with statistics
        """
        try:
            db = get_db()
            db_stats = db.get_database_stats()

            # Get device counts by status
            devices = db.get_all_devices()
            known_count = len([d for d in devices if d['status'] == 'known'])
            neutral_count = len([d for d in devices if d['status'] == 'neutral'])
            suspicious_count = len([d for d in devices if d['status'] == 'suspicious'])

            stats = {
                'database': db_stats,
                'devices_by_status': {
                    'known': known_count,
                    'neutral': neutral_count,
                    'suspicious': suspicious_count
                },
                'total_devices': len(devices)
            }

            # Add fingerprinting stats if available (Phase 2)
            try:
                from app.fingerprint_manager import get_fingerprint_manager
                manager = get_fingerprint_manager()
                stats['fingerprinting'] = manager.get_statistics()
            except Exception:
                # Fingerprinting not initialized yet
                pass

            # Add location stats if available (Phase 3)
            try:
                from app.location import get_location_detector
                detector = get_location_detector()
                stats['location'] = detector.get_statistics()
            except Exception:
                # Location detection not initialized yet
                pass

            return jsonify(stats)

        except Exception as e:
            logger.error(f"Error getting statistics: {e}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    # ==========================================
    # Health Check
    # ==========================================

    @app.route('/health')
    def health():
        """Health check endpoint."""
        return jsonify({'status': 'healthy', 'message': 'Plumbus is operational!'})

    logger.info("Flask routes registered")


# Test the app
if __name__ == '__main__':
    print("Testing Flask Application...")

    app = create_app()
    print(f"App created: {app.name}")
    print(f"Debug mode: {app.debug}")
    print("\nRegistered routes:")
    for rule in app.url_map.iter_rules():
        print(f"  {rule.rule} -> {rule.endpoint}")

    print("\nTo run the app:")
    print("  flask run")
    print("  or")
    print("  python3 run.py")
