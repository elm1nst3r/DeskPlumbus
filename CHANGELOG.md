# WiFi Desk Plumbus - Changelog

All notable changes to this project will be documented in this file.

## [1.1.0] - Management & Export Features - 2026-01-07

### Added - Management Features

**Device Management Page**
- Comprehensive device management interface at `/devices`
- Device renaming with custom names
- SSID pool viewer showing all probed networks
- Device status management (Known, Neutral, Suspicious)
- Sortable device table with statistics
- Real-time device count and status breakdown
- Modal-based editing interface

**Location Management Page**
- Dedicated location management interface at `/locations`
- Location renaming with custom names
- BSSID pool viewer showing WiFi network fingerprints
- Location statistics (visit count, network count)
- Current location highlighting
- Grid layout with location cards
- First/last seen timestamps

**Alert Management System**
- Interactive alert cards with action buttons
- **Dismiss** - Mark alerts as resolved
- **Star** - Flag alerts for close monitoring (high priority)
- **View Device** - Opens detailed device history modal
- Visual indicators for starred alerts (gold highlight, ⭐ icon)
- Resolved alert tracking with green checkmarks
- Alert status persistence

**Device Detail Modal**
- Comprehensive device history viewer
- Device information panel (status, first/last seen, total probes)
- SSID fingerprint pool display with badges
- Location sightings with visit counts and timestamps
- Recent probe request history (last 100 requests)
- Associated alerts timeline
- All data fetched from new `/api/devices/<id>/history` endpoint

**Settings Page**
- Beautiful settings interface at `/settings`
- Organized into sections: Export Data and Version Management

**Data Export System**
- 6 CSV export options:
  - Export Devices (fingerprints, status, SSIDs, timestamps)
  - Export Locations (names, BSSIDs, detection history)
  - Export Probes (last 10,000 probe requests)
  - Export Networks (last 10,000 network observations)
  - Export Alerts (all alerts with resolution status)
  - Export All Data (ZIP file with all 5 CSVs)
- Timestamped filenames (e.g., `plumbus_devices_20260107_154234.csv`)
- Proper CSV headers and formatting
- Human-readable timestamps
- In-memory CSV generation for efficiency
- Download progress indicators

**Version Management**
- GitHub integration for update checking
- Current version display (v1.0.0)
- Latest release version from GitHub API
- Semantic version comparison
- Update availability detection
- Changelog display from GitHub releases
- One-click update mechanism
- Automatic git pull and dependency installation
- Auto-restart after successful update
- Error handling for network issues
- Repository link: `github.com/elm1nst3r/DeskPlumbus`

### Added - API Endpoints

**Device Management**
- `GET /devices` - Device management page
- `PUT /api/devices/<device_id>/name` - Update device custom name
- `POST /api/devices/<device_id>/status` - Update device status
- `GET /api/devices/<device_id>/history` - Get comprehensive device history

**Location Management**
- `GET /locations` - Location management page
- `PUT /api/locations/<location_id>/name` - Update location custom name

**Alert Management**
- `POST /api/alerts/<alert_id>/dismiss` - Dismiss/resolve alert
- `POST /api/alerts/<alert_id>/star` - Star alert for monitoring

**Settings & Export**
- `GET /settings` - Settings page
- `GET /api/export/devices` - Export devices as CSV
- `GET /api/export/locations` - Export locations as CSV
- `GET /api/export/probes` - Export probe requests as CSV
- `GET /api/export/networks` - Export network observations as CSV
- `GET /api/export/alerts` - Export alerts as CSV
- `GET /api/export/all` - Export all data as ZIP file

**Version Management**
- `GET /api/version/check` - Check GitHub for latest release
- `POST /api/version/update` - Perform git pull update

### Changed

**User Interface**
- Removed all "Phase X" titles from UI
- Updated card headers to be descriptive:
  - "Live Dashboard" (was "Phase 5 Real-time Analytics")
  - "Device Fingerprinting Statistics" (was "Phase 2")
  - "Current Location" (was "Phase 3")
  - "Following Device Alerts" (was "Phase 4")
  - "Device Activity Timeline" (was "Phase 5")
- Footer updated to "Surveillance Detection System"

**Navigation**
- Added Settings link to all page navigation bars
- Navigation now includes: Dashboard, Devices, Locations, Settings, Logout
- Consistent navbar across all pages
- Active page highlighting

**Alerts Display**
- Alerts now hoverable with smooth transitions
- Clickable alerts for device details
- Color-coded action buttons
- Better visual hierarchy

### Dependencies
- Added `requests>=2.31.0` for GitHub API integration

### Files Added
- `web/templates/devices.html` (565 lines) - Device management interface
- `web/templates/locations.html` (471 lines) - Location management interface
- `web/templates/settings.html` (350 lines) - Settings and export interface

### Files Modified
- `app/api.py` - Added 12 new endpoints (+600 lines)
- `web/templates/index.html` - Alert management UI, device detail modal, nav updates
- `requirements.txt` - Added requests library
- All template files - Updated navigation to include Settings

### Technical Improvements
- Modal-based UI for better UX
- CSV generation in memory (no temp files)
- ZIP file compression for bulk exports
- Proper HTTP headers for downloads (Content-Disposition)
- GitHub API integration with proper error handling
- Version comparison using semantic versioning
- Git operations with safety checks
- Session-based alert state management

## [1.0.0] - Phase 6: Production Polish - 2026-01-07

### Added - Phase 6 Features

**Authentication & Security**
- Password-protected web interface with session-based authentication
- Beautiful login page with Plumbus theme
- Configurable password via environment variables
- Logout functionality
- Session timeout (30 days default)

**Environment Configuration**
- `.env.example` template with all configuration options
- Environment variable support for all settings
- Automatic secret key generation during installation
- Secure credential management

**Advanced Logging**
- Rotating log file handler (10MB max, 5 backups)
- Configurable log levels (DEBUG, INFO, WARNING, ERROR, CRITICAL)
- Structured log format with timestamps
- Console and file output
- Automatic log rotation
- Suppressed noisy third-party loggers

**Database Optimization**
- Added 11 new performance indexes:
  - `idx_devices_status_lastseen` - Composite index for status + last_seen queries
  - `idx_devices_lastseen` - Time-based device queries
  - `idx_locations_lastseen` - Recent locations lookup
  - `idx_network_obs_bssid` - BSSID lookups
  - `idx_network_obs_location_time` - Location + timestamp composite
  - `idx_network_obs_bssid_time` - BSSID + timestamp composite
  - `idx_probe_requests_device` - Device history lookup
  - `idx_probe_requests_mac_time` - MAC + timestamp composite
  - `idx_alerts_device` - Device alert history
  - `idx_alerts_status_created` - Status + created_at composite
  - `idx_alerts_type` - Alert type filtering
- Improved query performance for time-based and filtered queries
- Optimized foreign key lookups

**Production Deployment**
- Updated systemd service configuration:
  - Environment file support (.env)
  - Improved restart policies
  - Enhanced resource limits for Pi Zero W
  - WiFi cleanup on service stop
  - Better kill policies
  - Security hardening options (commented)
- Updated installation script (install.sh):
  - 9-step installation process
  - Environment file setup with random secret key generation
  - Database initialization with indexes
  - Firewall configuration (port 5001)
  - Phase 6 features documentation
  - Improved completion message

### Changed

**Configuration**
- Moved Flask port from 5000 to 5001 (avoid macOS Control Center conflict)
- All documentation updated to reflect port 5001
- README updated with Phase 0-5 completion status
- Added Phase 6 roadmap section

**Documentation**
- Updated README with Phase 5 WebSocket features
- Added authentication documentation
- Updated firewall instructions
- Added environment configuration guide
- Updated installation steps

### Fixed
- Port 5000 conflict with macOS Control Center
- Missing authentication on web routes
- Inconsistent logging across modules

## [1.0.0-beta] - Phase 5: Real-time Analytics - 2026-01-07

### Added - Phase 5 Features

**Real-time WebSocket Updates**
- Flask-SocketIO integration with eventlet
- Background broadcast task (2-second interval)
- 8 WebSocket event streams:
  - `status_update` - System status
  - `statistics_update` - Database statistics
  - `fingerprint_stats_update` - Phase 2 fingerprinting
  - `location_update` - Phase 3 location data
  - `following_stats_update` - Phase 4 correlation
  - `alerts_update` - Recent alerts
  - `devices_update` - Device list
  - `new_alert` - Real-time alert notifications

**Dashboard Enhancements**
- Live WebSocket client with Socket.IO
- Connection status indicator (green/red dot)
- Toast notifications for alerts and connection events
- Auto-dismiss notifications
- Removed polling (replaced with WebSocket push)

**Data Visualization**
- Chart.js integration
- Device activity timeline chart
- 3 real-time data streams:
  - Devices Detected
  - Probe Requests
  - Networks Visible
- Rolling 20 data point window
- Smooth updates without animation lag

**Phase 4 Display**
- Following device alerts section
- Up to 5 most recent alerts displayed
- Alert details with device ID and timestamp
- Following detection statistics panel

### Changed
- Replaced 5-second REST API polling with 2-second WebSocket updates
- Updated dashboard to Phase 5 theme
- Improved implementation progress list

## [0.9.0] - Phase 4: Following Device Detection - 2026-01-06

### Added - Phase 4 Features
- Cross-location device tracking
- Movement correlation scoring
- Alert system for suspicious devices
- Device whitelist management
- Device status API endpoints

## [0.8.0] - Phase 3: Location Detection - 2026-01-06

### Added - Phase 3 Features
- BSSID pool location fingerprinting
- Automatic location detection
- Location tracking & management
- Location statistics & analytics

## [0.7.0] - Phase 2: SSID Fingerprinting - 2026-01-06

### Added - Phase 2 Features
- SSID pool extraction from probe requests
- Jaccard similarity matching
- MAC randomization defeat
- Device fingerprint database

## [0.6.0] - Phase 1: Core WiFi Monitoring - 2026-01-06

### Added - Phase 1 Features
- WiFi monitor mode management
- Network scanner (2.4 GHz + 5 GHz)
- Scapy packet capture
- Basic Flask web dashboard
- SQLite database operations

## [0.5.0] - Phase 0: Project Foundation - 2026-01-06

### Added - Phase 0 Features
- Project structure
- Configuration management
- Installation scripts
- Database schema
- Documentation (README, .gitignore)

---

## Version Format
Format: `MAJOR.MINOR.PATCH`
- **MAJOR**: Major phases (1.0.0 = Phase 6 complete)
- **MINOR**: Feature additions
- **PATCH**: Bug fixes

## Links
- [GitHub Repository](https://github.com/elm1nst3r/DeskPlumbus)
- [Issues](https://github.com/elm1nst3r/DeskPlumbus/issues)
