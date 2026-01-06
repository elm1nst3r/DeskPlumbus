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
