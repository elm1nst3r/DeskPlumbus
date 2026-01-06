"""
WiFi Desk Plumbus - Flask API Module

This module provides RESTful API endpoints and web interface for the Plumbus Sentinel.

Phase 1 Implementation:
- Basic Flask application setup
- System status endpoint
- Network list endpoint
- Simple dashboard
"""

import logging
from datetime import datetime
from flask import Flask, jsonify, render_template, request
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

    return app


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
