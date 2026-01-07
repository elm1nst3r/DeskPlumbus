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
from app.auth import init_auth, login_required

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

    # Initialize authentication (Phase 6)
    init_auth(app)

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
    @login_required
    def index():
        """Render main dashboard."""
        return render_template('index.html')

    @app.route('/devices')
    @login_required
    def devices_page():
        """Render device management page (Phase 6)."""
        return render_template('devices.html')

    @app.route('/locations')
    @login_required
    def locations_page():
        """Render location management page (Phase 6)."""
        return render_template('locations.html')

    @app.route('/test/websocket')
    @login_required
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

    @app.route('/api/devices/<device_id>/name', methods=['PUT'])
    def api_update_device_name(device_id):
        """
        Update device custom name (Phase 6).

        Args:
            device_id: Device fingerprint ID

        Request JSON:
            {
                "name": "My iPhone"
            }

        Returns:
            JSON with success message
        """
        try:
            data = request.get_json()
            new_name = data.get('name', '').strip()

            if not new_name:
                return jsonify({'error': 'Name cannot be empty'}), 400

            if len(new_name) > 100:
                return jsonify({'error': 'Name too long (max 100 characters)'}), 400

            # Update device name in database
            db = get_db()
            db.update_device(device_id, custom_name=new_name)

            return jsonify({
                'success': True,
                'message': f'Device renamed to "{new_name}"',
                'device_id': device_id,
                'name': new_name
            })

        except Exception as e:
            logger.error(f"Error updating device name: {e}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    @app.route('/api/locations/<location_id>/name', methods=['PUT'])
    def api_update_location_name(location_id):
        """
        Update location custom name (Phase 6).

        Args:
            location_id: Location identifier

        Request JSON:
            {
                "name": "Home"
            }

        Returns:
            JSON with success message
        """
        try:
            data = request.get_json()
            new_name = data.get('name', '').strip()

            if not new_name:
                return jsonify({'error': 'Name cannot be empty'}), 400

            if len(new_name) > 100:
                return jsonify({'error': 'Name too long (max 100 characters)'}), 400

            # Update location name
            from app.location import get_location_detector
            detector = get_location_detector()

            if location_id in detector.locations:
                location = detector.locations[location_id]
                location.name = new_name
                detector.save_location_to_database(location)

                return jsonify({
                    'success': True,
                    'message': f'Location renamed to "{new_name}"',
                    'location_id': location_id,
                    'name': new_name
                })
            else:
                return jsonify({'error': 'Location not found'}), 404

        except Exception as e:
            logger.error(f"Error updating location name: {e}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    @app.route('/api/alerts/<int:alert_id>/dismiss', methods=['POST'])
    def api_dismiss_alert(alert_id):
        """
        Dismiss an alert.

        Args:
            alert_id: Alert ID

        Returns:
            JSON with success message
        """
        try:
            db = get_db()

            # Update alert status to resolved
            with db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE alerts
                    SET status = 'resolved',
                        resolved_at = strftime('%s', 'now')
                    WHERE id = ?
                """, (alert_id,))

                if cursor.rowcount == 0:
                    return jsonify({'error': 'Alert not found'}), 404

            return jsonify({
                'success': True,
                'message': 'Alert dismissed',
                'alert_id': alert_id
            })

        except Exception as e:
            logger.error(f"Error dismissing alert: {e}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    @app.route('/api/alerts/<int:alert_id>/star', methods=['POST'])
    def api_star_alert(alert_id):
        """
        Star/flag an alert for close monitoring.

        Args:
            alert_id: Alert ID

        Returns:
            JSON with success message
        """
        try:
            db = get_db()

            # Add a starred/priority flag to the alert
            with db.get_connection() as conn:
                cursor = conn.cursor()

                # Check if alert exists
                cursor.execute("SELECT status FROM alerts WHERE id = ?", (alert_id,))
                result = cursor.fetchone()

                if not result:
                    return jsonify({'error': 'Alert not found'}), 404

                # Update severity to high (indicating starred/priority)
                cursor.execute("""
                    UPDATE alerts
                    SET severity = 'high'
                    WHERE id = ?
                """, (alert_id,))

            return jsonify({
                'success': True,
                'message': 'Alert starred for monitoring',
                'alert_id': alert_id
            })

        except Exception as e:
            logger.error(f"Error starring alert: {e}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    @app.route('/api/devices/<device_id>/history')
    def api_device_history(device_id):
        """
        Get detailed history of when and where a device was seen.

        Args:
            device_id: Device fingerprint ID

        Returns:
            JSON with device history
        """
        try:
            db = get_db()

            # Get device info
            device = db.get_device(device_id)
            if not device:
                return jsonify({'error': 'Device not found'}), 404

            # Get probe requests for this device
            with db.get_connection() as conn:
                cursor = conn.cursor()

                # Get probe request history
                cursor.execute("""
                    SELECT
                        mac_address,
                        ssid,
                        frequency_band,
                        timestamp
                    FROM probe_requests
                    WHERE device_fingerprint_id = ?
                    ORDER BY timestamp DESC
                    LIMIT 1000
                """, (device_id,))

                probes = []
                for row in cursor.fetchall():
                    probes.append({
                        'mac_address': row[0],
                        'ssid': row[1],
                        'frequency_band': row[2],
                        'timestamp': row[3]
                    })

                # Get alerts for this device
                cursor.execute("""
                    SELECT
                        id,
                        alert_type,
                        severity,
                        message,
                        status,
                        created_at,
                        resolved_at
                    FROM alerts
                    WHERE device_fingerprint_id = ?
                    ORDER BY created_at DESC
                """, (device_id,))

                alerts = []
                for row in cursor.fetchall():
                    alerts.append({
                        'id': row[0],
                        'alert_type': row[1],
                        'severity': row[2],
                        'message': row[3],
                        'status': row[4],
                        'created_at': row[5],
                        'resolved_at': row[6]
                    })

            # Get location sightings
            from app.following import get_following_detector
            detector = get_following_detector()

            location_sightings = []
            if device_id in detector.device_locations:
                for loc_id, timestamps in detector.device_locations[device_id].items():
                    location_sightings.append({
                        'location_id': loc_id,
                        'visit_count': len(timestamps),
                        'first_seen': min(timestamps),
                        'last_seen': max(timestamps),
                        'timestamps': sorted(timestamps, reverse=True)[:10]  # Last 10 visits
                    })

            return jsonify({
                'device': device,
                'probe_history': probes[:100],  # Last 100 probes
                'location_sightings': location_sightings,
                'alerts': alerts,
                'total_probes': len(probes),
                'total_locations': len(location_sightings)
            })

        except Exception as e:
            logger.error(f"Error getting device history: {e}", exc_info=True)
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
    # Settings Page
    # ==========================================

    @app.route('/settings')
    @login_required
    def settings_page():
        """Render settings page."""
        return render_template('settings.html')

    # ==========================================
    # Export Data Endpoints
    # ==========================================

    @app.route('/api/export/devices')
    @login_required
    def api_export_devices():
        """Export devices data as CSV."""
        try:
            import csv
            import io
            from flask import make_response

            db = get_db()
            devices = db.get_all_devices()

            # Create CSV in memory
            output = io.StringIO()
            writer = csv.writer(output)

            # Write header
            writer.writerow(['Fingerprint ID', 'Custom Name', 'Status', 'SSID Count', 'MAC Addresses', 'First Seen', 'Last Seen', 'Detection Count'])

            # Write data
            for device in devices:
                writer.writerow([
                    device['fingerprint_id'],
                    device.get('custom_name') or 'Unknown Device',
                    device['status'],
                    device['ssid_count'],
                    device['mac_count'],
                    datetime.fromtimestamp(device['first_seen']).strftime('%Y-%m-%d %H:%M:%S') if device.get('first_seen') else '',
                    datetime.fromtimestamp(device['last_seen']).strftime('%Y-%m-%d %H:%M:%S') if device.get('last_seen') else '',
                    device['detection_count']
                ])

            # Create response
            response = make_response(output.getvalue())
            response.headers['Content-Type'] = 'text/csv'
            response.headers['Content-Disposition'] = f'attachment; filename="plumbus_devices_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv"'

            return response

        except Exception as e:
            logger.error(f"Error exporting devices: {e}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    @app.route('/api/export/locations')
    @login_required
    def api_export_locations():
        """Export locations data as CSV."""
        try:
            import csv
            import io
            from flask import make_response

            db = get_db()
            locations = db.get_all_locations()

            # Create CSV in memory
            output = io.StringIO()
            writer = csv.writer(output)

            # Write header
            writer.writerow(['Location ID', 'Name', 'BSSID Count', 'First Detected', 'Last Detected', 'Detection Count'])

            # Write data
            for location in locations:
                writer.writerow([
                    location['location_id'],
                    location['name'],
                    location['bssid_count'],
                    datetime.fromtimestamp(location['first_detected']).strftime('%Y-%m-%d %H:%M:%S'),
                    datetime.fromtimestamp(location['last_detected']).strftime('%Y-%m-%d %H:%M:%S'),
                    location['detection_count']
                ])

            # Create response
            response = make_response(output.getvalue())
            response.headers['Content-Type'] = 'text/csv'
            response.headers['Content-Disposition'] = f'attachment; filename="plumbus_locations_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv"'

            return response

        except Exception as e:
            logger.error(f"Error exporting locations: {e}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    @app.route('/api/export/probes')
    @login_required
    def api_export_probes():
        """Export probe requests data as CSV."""
        try:
            import csv
            import io
            from flask import make_response

            db = get_db()

            with db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT mac_address, ssid, timestamp, fingerprint_id
                    FROM probe_requests
                    ORDER BY timestamp DESC
                    LIMIT 10000
                """)
                probes = cursor.fetchall()

            # Create CSV in memory
            output = io.StringIO()
            writer = csv.writer(output)

            # Write header
            writer.writerow(['MAC Address', 'SSID', 'Timestamp', 'Device ID'])

            # Write data
            for probe in probes:
                writer.writerow([
                    probe[0],
                    probe[1] or '(broadcast)',
                    datetime.fromtimestamp(probe[2]).strftime('%Y-%m-%d %H:%M:%S'),
                    probe[3] or 'Unidentified'
                ])

            # Create response
            response = make_response(output.getvalue())
            response.headers['Content-Type'] = 'text/csv'
            response.headers['Content-Disposition'] = f'attachment; filename="plumbus_probes_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv"'

            return response

        except Exception as e:
            logger.error(f"Error exporting probes: {e}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    @app.route('/api/export/networks')
    @login_required
    def api_export_networks():
        """Export network observations data as CSV."""
        try:
            import csv
            import io
            from flask import make_response

            db = get_db()

            with db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT bssid, ssid, frequency_band, timestamp, location_id
                    FROM network_observations
                    ORDER BY timestamp DESC
                    LIMIT 10000
                """)
                networks = cursor.fetchall()

            # Create CSV in memory
            output = io.StringIO()
            writer = csv.writer(output)

            # Write header
            writer.writerow(['BSSID', 'SSID', 'Frequency Band', 'Timestamp', 'Location ID'])

            # Write data
            for network in networks:
                writer.writerow([
                    network[0],
                    network[1] or '(hidden)',
                    network[2] or '2.4GHz',
                    datetime.fromtimestamp(network[3]).strftime('%Y-%m-%d %H:%M:%S'),
                    network[4] or 'Unknown'
                ])

            # Create response
            response = make_response(output.getvalue())
            response.headers['Content-Type'] = 'text/csv'
            response.headers['Content-Disposition'] = f'attachment; filename="plumbus_networks_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv"'

            return response

        except Exception as e:
            logger.error(f"Error exporting networks: {e}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    @app.route('/api/export/alerts')
    @login_required
    def api_export_alerts():
        """Export alerts data as CSV."""
        try:
            import csv
            import io
            from flask import make_response

            db = get_db()

            with db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT alert_type, device_id, message, severity, status, timestamp, resolved_at
                    FROM alerts
                    ORDER BY timestamp DESC
                """)
                alerts = cursor.fetchall()

            # Create CSV in memory
            output = io.StringIO()
            writer = csv.writer(output)

            # Write header
            writer.writerow(['Alert Type', 'Device ID', 'Message', 'Severity', 'Status', 'Timestamp', 'Resolved At'])

            # Write data
            for alert in alerts:
                writer.writerow([
                    alert[0],
                    alert[1] or 'Unknown',
                    alert[2],
                    alert[3],
                    alert[4],
                    datetime.fromtimestamp(alert[5]).strftime('%Y-%m-%d %H:%M:%S'),
                    datetime.fromtimestamp(alert[6]).strftime('%Y-%m-%d %H:%M:%S') if alert[6] else ''
                ])

            # Create response
            response = make_response(output.getvalue())
            response.headers['Content-Type'] = 'text/csv'
            response.headers['Content-Disposition'] = f'attachment; filename="plumbus_alerts_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv"'

            return response

        except Exception as e:
            logger.error(f"Error exporting alerts: {e}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    @app.route('/api/export/all')
    @login_required
    def api_export_all():
        """Export all data as a ZIP file containing multiple CSVs."""
        try:
            import csv
            import io
            import zipfile
            from flask import make_response

            db = get_db()

            # Create ZIP file in memory
            zip_buffer = io.BytesIO()

            with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                # Export devices
                devices = db.get_all_devices()
                devices_csv = io.StringIO()
                writer = csv.writer(devices_csv)
                writer.writerow(['Fingerprint ID', 'Custom Name', 'Status', 'SSID Count', 'MAC Addresses', 'First Seen', 'Last Seen', 'Detection Count'])
                for device in devices:
                    writer.writerow([
                        device['fingerprint_id'],
                        device.get('custom_name') or 'Unknown Device',
                        device['status'],
                        device['ssid_count'],
                        device['mac_count'],
                        datetime.fromtimestamp(device['first_seen']).strftime('%Y-%m-%d %H:%M:%S') if device.get('first_seen') else '',
                        datetime.fromtimestamp(device['last_seen']).strftime('%Y-%m-%d %H:%M:%S') if device.get('last_seen') else '',
                        device['detection_count']
                    ])
                zip_file.writestr('devices.csv', devices_csv.getvalue())

                # Export locations
                locations = db.get_all_locations()
                locations_csv = io.StringIO()
                writer = csv.writer(locations_csv)
                writer.writerow(['Location ID', 'Name', 'BSSID Count', 'First Detected', 'Last Detected', 'Detection Count'])
                for location in locations:
                    writer.writerow([
                        location['location_id'],
                        location['name'],
                        location['bssid_count'],
                        datetime.fromtimestamp(location['first_detected']).strftime('%Y-%m-%d %H:%M:%S'),
                        datetime.fromtimestamp(location['last_detected']).strftime('%Y-%m-%d %H:%M:%S'),
                        location['detection_count']
                    ])
                zip_file.writestr('locations.csv', locations_csv.getvalue())

                # Export probes (limit to last 10000)
                with db.get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                        SELECT mac_address, ssid, timestamp, fingerprint_id
                        FROM probe_requests
                        ORDER BY timestamp DESC
                        LIMIT 10000
                    """)
                    probes = cursor.fetchall()

                probes_csv = io.StringIO()
                writer = csv.writer(probes_csv)
                writer.writerow(['MAC Address', 'SSID', 'Timestamp', 'Device ID'])
                for probe in probes:
                    writer.writerow([
                        probe[0],
                        probe[1] or '(broadcast)',
                        datetime.fromtimestamp(probe[2]).strftime('%Y-%m-%d %H:%M:%S'),
                        probe[3] or 'Unidentified'
                    ])
                zip_file.writestr('probes.csv', probes_csv.getvalue())

                # Export networks (limit to last 10000)
                with db.get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                        SELECT bssid, ssid, frequency_band, timestamp, location_id
                        FROM network_observations
                        ORDER BY timestamp DESC
                        LIMIT 10000
                    """)
                    networks = cursor.fetchall()

                networks_csv = io.StringIO()
                writer = csv.writer(networks_csv)
                writer.writerow(['BSSID', 'SSID', 'Frequency Band', 'Timestamp', 'Location ID'])
                for network in networks:
                    writer.writerow([
                        network[0],
                        network[1] or '(hidden)',
                        network[2] or '2.4GHz',
                        datetime.fromtimestamp(network[3]).strftime('%Y-%m-%d %H:%M:%S'),
                        network[4] or 'Unknown'
                    ])
                zip_file.writestr('networks.csv', networks_csv.getvalue())

                # Export alerts
                with db.get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                        SELECT alert_type, device_id, message, severity, status, timestamp, resolved_at
                        FROM alerts
                        ORDER BY timestamp DESC
                    """)
                    alerts = cursor.fetchall()

                alerts_csv = io.StringIO()
                writer = csv.writer(alerts_csv)
                writer.writerow(['Alert Type', 'Device ID', 'Message', 'Severity', 'Status', 'Timestamp', 'Resolved At'])
                for alert in alerts:
                    writer.writerow([
                        alert[0],
                        alert[1] or 'Unknown',
                        alert[2],
                        alert[3],
                        alert[4],
                        datetime.fromtimestamp(alert[5]).strftime('%Y-%m-%d %H:%M:%S'),
                        datetime.fromtimestamp(alert[6]).strftime('%Y-%m-%d %H:%M:%S') if alert[6] else ''
                    ])
                zip_file.writestr('alerts.csv', alerts_csv.getvalue())

            # Create response
            zip_buffer.seek(0)
            response = make_response(zip_buffer.getvalue())
            response.headers['Content-Type'] = 'application/zip'
            response.headers['Content-Disposition'] = f'attachment; filename="plumbus_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.zip"'

            return response

        except Exception as e:
            logger.error(f"Error exporting all data: {e}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    # ==========================================
    # Version Management Endpoints
    # ==========================================

    @app.route('/api/version/check')
    @login_required
    def api_version_check():
        """Check for updates from GitHub."""
        try:
            import requests
            import re

            # Get current version
            current_version = config.APP_VERSION

            # Fetch latest release from GitHub
            github_api = "https://api.github.com/repos/elm1nst3r/DeskPlumbus/releases/latest"
            headers = {'Accept': 'application/vnd.github.v3+json'}

            response = requests.get(github_api, headers=headers, timeout=10)
            response.raise_for_status()

            latest_release = response.json()
            latest_version = latest_release['tag_name'].lstrip('v')

            # Compare versions
            def version_tuple(v):
                return tuple(map(int, (v.split('.'))))

            current_tuple = version_tuple(current_version)
            latest_tuple = version_tuple(latest_version)

            update_available = latest_tuple > current_tuple

            # Get changelog
            changelog = latest_release.get('body', 'No changelog available')

            return jsonify({
                'success': True,
                'current_version': current_version,
                'latest_version': latest_version,
                'update_available': update_available,
                'changelog': changelog,
                'release_url': latest_release.get('html_url'),
                'published_at': latest_release.get('published_at')
            })

        except requests.RequestException as e:
            logger.error(f"Error checking for updates: {e}", exc_info=True)
            return jsonify({
                'success': False,
                'error': 'Unable to connect to GitHub. Please check your internet connection.'
            }), 503

        except Exception as e:
            logger.error(f"Error in version check: {e}", exc_info=True)
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    @app.route('/api/version/update', methods=['POST'])
    @login_required
    def api_version_update():
        """Perform update from GitHub."""
        try:
            import subprocess
            import os

            # Get project directory
            project_dir = config.BASE_DIR

            # Check if we're in a git repository
            git_check = subprocess.run(
                ['git', 'rev-parse', '--is-inside-work-tree'],
                cwd=project_dir,
                capture_output=True,
                text=True
            )

            if git_check.returncode != 0:
                return jsonify({
                    'success': False,
                    'message': 'Not a git repository. Please update manually.'
                }), 400

            # Pull latest changes
            logger.info("Pulling latest changes from GitHub...")
            pull_result = subprocess.run(
                ['git', 'pull', 'origin', 'main'],
                cwd=project_dir,
                capture_output=True,
                text=True
            )

            if pull_result.returncode != 0:
                return jsonify({
                    'success': False,
                    'message': f'Git pull failed: {pull_result.stderr}'
                }), 500

            # Install/update dependencies
            logger.info("Installing dependencies...")
            pip_result = subprocess.run(
                ['pip3', 'install', '-r', 'requirements.txt'],
                cwd=project_dir,
                capture_output=True,
                text=True
            )

            if pip_result.returncode != 0:
                logger.warning(f"Dependency installation had warnings: {pip_result.stderr}")

            # Schedule restart (the systemd service will auto-restart)
            logger.info("Update successful! Scheduling restart...")

            # Return success - the client will reload after 5 seconds
            return jsonify({
                'success': True,
                'message': 'Update successful! Restarting application...',
                'output': pull_result.stdout
            })

        except Exception as e:
            logger.error(f"Error performing update: {e}", exc_info=True)
            return jsonify({
                'success': False,
                'message': str(e)
            }), 500

    # ==========================================
    # WiFi Management Endpoints
    # ==========================================

    @app.route('/api/wifi/status')
    @login_required
    def api_wifi_status():
        """Get WiFi manager status."""
        try:
            from app.wifi_manager import get_wifi_manager

            manager = get_wifi_manager()
            status = manager.get_status()

            return jsonify({
                'success': True,
                **status
            })

        except Exception as e:
            logger.error(f"Error getting WiFi status: {e}", exc_info=True)
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    @app.route('/api/wifi/scan')
    @login_required
    def api_wifi_scan():
        """Scan for available WiFi networks."""
        try:
            from app.wifi_manager import get_wifi_manager

            manager = get_wifi_manager()
            networks = manager.scan_networks()

            # Convert to dicts
            networks_data = [
                {
                    'ssid': n.ssid,
                    'bssid': n.bssid,
                    'frequency': n.frequency,
                    'signal_strength': n.signal_strength,
                    'encryption': n.encryption,
                    'channel': n.channel
                }
                for n in networks
            ]

            return jsonify({
                'success': True,
                'networks': networks_data,
                'count': len(networks_data)
            })

        except Exception as e:
            logger.error(f"Error scanning networks: {e}", exc_info=True)
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    @app.route('/api/wifi/connect', methods=['POST'])
    @login_required
    def api_wifi_connect():
        """Connect to a WiFi network."""
        try:
            from app.wifi_manager import get_wifi_manager

            data = request.get_json()
            ssid = data.get('ssid')
            password = data.get('password', '')

            if not ssid:
                return jsonify({
                    'success': False,
                    'message': 'SSID is required'
                }), 400

            manager = get_wifi_manager()
            success, message = manager.connect_to_network(ssid, password)

            return jsonify({
                'success': success,
                'message': message
            })

        except Exception as e:
            logger.error(f"Error connecting to network: {e}", exc_info=True)
            return jsonify({
                'success': False,
                'message': str(e)
            }), 500

    @app.route('/api/wifi/profiles')
    @login_required
    def api_wifi_profiles():
        """Get saved WiFi network profiles."""
        try:
            from app.wifi_manager import get_wifi_manager

            manager = get_wifi_manager()

            profiles_data = [
                {
                    'ssid': p.ssid,
                    'priority': p.priority,
                    'auto_connect': p.auto_connect
                }
                for p in manager.profiles
            ]

            return jsonify({
                'success': True,
                'profiles': profiles_data
            })

        except Exception as e:
            logger.error(f"Error getting profiles: {e}", exc_info=True)
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    @app.route('/api/wifi/profiles/<ssid>', methods=['DELETE'])
    @login_required
    def api_wifi_delete_profile(ssid):
        """Delete a saved network profile."""
        try:
            from app.wifi_manager import get_wifi_manager

            manager = get_wifi_manager()

            # Find and remove profile
            manager.profiles = [p for p in manager.profiles if p.ssid != ssid]
            manager._save_profiles()

            return jsonify({
                'success': True,
                'message': f'Profile "{ssid}" deleted'
            })

        except Exception as e:
            logger.error(f"Error deleting profile: {e}", exc_info=True)
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    @app.route('/api/wifi/interfaces/swap', methods=['POST'])
    @login_required
    def api_wifi_swap_interfaces():
        """Swap surveillance and management interface assignments."""
        try:
            from app.wifi_manager import get_wifi_manager

            manager = get_wifi_manager()
            success, message = manager.swap_interfaces()

            return jsonify({
                'success': success,
                'message': message
            })

        except Exception as e:
            logger.error(f"Error swapping interfaces: {e}", exc_info=True)
            return jsonify({
                'success': False,
                'message': str(e)
            }), 500

    @app.route('/api/wifi/interfaces/assign', methods=['POST'])
    @login_required
    def api_wifi_assign_interfaces():
        """Manually assign interfaces to surveillance and management roles."""
        try:
            from app.wifi_manager import get_wifi_manager

            data = request.get_json()
            surveillance = data.get('surveillance')
            management = data.get('management')

            if not surveillance or not management:
                return jsonify({
                    'success': False,
                    'message': 'Both surveillance and management interfaces required'
                }), 400

            manager = get_wifi_manager()
            success, message = manager.set_interface_assignment(surveillance, management)

            return jsonify({
                'success': success,
                'message': message
            })

        except Exception as e:
            logger.error(f"Error assigning interfaces: {e}", exc_info=True)
            return jsonify({
                'success': False,
                'message': str(e)
            }), 500

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
