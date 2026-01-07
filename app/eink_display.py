"""
WiFi Desk Plumbus - E-Ink Display Manager

Optional e-ink display support for Waveshare 2.13" e-Paper HAT.
Provides local status display when web interface is not accessible.

Features:
- Auto-detection (graceful fallback if not present)
- Multiple screen layouts (status, alerts, network scan)
- Smart refresh strategy (full vs partial refresh)
- Low power consumption
- Button support for navigation

Waveshare 2.13" e-Paper HAT Specs:
- Resolution: 250x122 pixels
- Interface: SPI
- Colors: Black/White (2-color)
- Refresh time: ~2 seconds (full), ~0.5 seconds (partial)
- Driver: EPD 2.13 inch V2/V3
"""

import logging
import time
from datetime import datetime
from typing import Optional, Dict, List
from enum import Enum
import os

try:
    # Try to import Waveshare e-Paper library
    # Install with: pip install waveshare-epd
    from waveshare_epd import epd2in13_V2
    from PIL import Image, ImageDraw, ImageFont
    EINK_AVAILABLE = True
except ImportError:
    EINK_AVAILABLE = False
    epd2in13_V2 = None
    Image = None
    ImageDraw = None
    ImageFont = None

import config

logger = logging.getLogger(__name__)


class DisplayScreen(Enum):
    """Available display screens."""
    STATUS = "status"           # Main status screen
    ALERTS = "alerts"          # Recent alerts
    NETWORKS = "networks"      # Network scan
    STATS = "stats"           # Statistics
    LOCATION = "location"     # Location info


class EInkDisplay:
    """
    Manages the optional Waveshare 2.13" e-Paper HAT display.

    Features:
    - Auto-detection with graceful fallback
    - Multiple screen layouts
    - Smart refresh management
    - Low power operation
    """

    def __init__(self):
        self.available = False
        self.epd = None
        self.width = 250  # Waveshare 2.13" width
        self.height = 122  # Waveshare 2.13" height
        self.current_screen = DisplayScreen.STATUS
        self.last_refresh = 0
        self.refresh_interval = 30  # Refresh every 30 seconds
        self.rotation = 0  # 0, 90, 180, 270

        # Fonts (will be loaded if display is available)
        self.font_large = None
        self.font_medium = None
        self.font_small = None
        self.font_tiny = None

        logger.info("E-Ink Display Manager initialized")

    def initialize(self) -> bool:
        """Initialize e-ink display if available."""
        if not EINK_AVAILABLE:
            logger.info("Waveshare e-Paper library not installed")
            logger.info("Install with: pip install waveshare-epd")
            return False

        try:
            logger.info("Detecting Waveshare 2.13\" e-Paper HAT...")

            # Try to initialize the display
            self.epd = epd2in13_V2.EPD()
            self.epd.init(self.epd.FULL_UPDATE)
            self.epd.Clear(0xFF)  # Clear to white

            # Load fonts
            self._load_fonts()

            self.available = True
            logger.info("✅ E-Ink display detected and initialized!")
            logger.info(f"  Resolution: {self.width}x{self.height}")
            logger.info(f"  Refresh interval: {self.refresh_interval}s")

            # Show boot screen
            self._show_boot_screen()

            return True

        except Exception as e:
            logger.warning(f"E-Ink display not available: {e}")
            logger.info("Continuing without e-ink display (web interface only)")
            self.available = False
            return False

    def _load_fonts(self):
        """Load fonts for display."""
        try:
            # Try to load system fonts
            font_paths = [
                "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
                "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
                "/System/Library/Fonts/Helvetica.ttc",  # macOS
                "C:\\Windows\\Fonts\\arial.ttf",  # Windows
            ]

            font_path = None
            for path in font_paths:
                if os.path.exists(path):
                    font_path = path
                    break

            if font_path:
                self.font_large = ImageFont.truetype(font_path, 24)
                self.font_medium = ImageFont.truetype(font_path, 16)
                self.font_small = ImageFont.truetype(font_path, 12)
                self.font_tiny = ImageFont.truetype(font_path, 10)
            else:
                # Fallback to default font
                self.font_large = ImageFont.load_default()
                self.font_medium = ImageFont.load_default()
                self.font_small = ImageFont.load_default()
                self.font_tiny = ImageFont.load_default()

            logger.info("Fonts loaded successfully")

        except Exception as e:
            logger.warning(f"Error loading fonts: {e}")
            # Use default font
            self.font_large = ImageFont.load_default()
            self.font_medium = ImageFont.load_default()
            self.font_small = ImageFont.load_default()
            self.font_tiny = ImageFont.load_default()

    def _show_boot_screen(self):
        """Display boot screen - compact."""
        image = Image.new('1', (self.width, self.height), 255)  # White background
        draw = ImageDraw.Draw(image)

        # Banner with inverted colors
        draw.rectangle([(0, 0), (self.width, 30)], fill=0)
        draw.text((5, 5), "PLUMBUS", font=self.font_large, fill=255)

        # Version and status
        y = 40
        draw.text((5, y), f"v{config.APP_VERSION}", font=self.font_small, fill=0)
        y += 16
        draw.text((5, y), "Initializing sensors...", font=self.font_tiny, fill=0)
        y += 12
        draw.text((5, y), "WiFi surveillance", font=self.font_tiny, fill=0)
        y += 12
        draw.text((5, y), "Device tracking", font=self.font_tiny, fill=0)

        # Footer
        draw.line([(0, self.height-14), (self.width, self.height-14)], fill=0)
        draw.text((5, self.height-12), "Everyone has one!", font=self.font_tiny, fill=0)

        self._display_image(image)

    def update(self, force: bool = False):
        """
        Update display with current information.

        Args:
            force: Force update even if refresh interval hasn't elapsed
        """
        if not self.available:
            return

        # Check if enough time has elapsed
        current_time = time.time()
        if not force and (current_time - self.last_refresh) < self.refresh_interval:
            return

        try:
            # Get data for current screen
            if self.current_screen == DisplayScreen.STATUS:
                self._show_status_screen()
            elif self.current_screen == DisplayScreen.ALERTS:
                self._show_alerts_screen()
            elif self.current_screen == DisplayScreen.NETWORKS:
                self._show_networks_screen()
            elif self.current_screen == DisplayScreen.STATS:
                self._show_stats_screen()
            elif self.current_screen == DisplayScreen.LOCATION:
                self._show_location_screen()

            self.last_refresh = current_time

        except Exception as e:
            logger.error(f"Error updating e-ink display: {e}", exc_info=True)

    def _show_status_screen(self):
        """Display main status screen - compact with following alert emphasis."""
        image = Image.new('1', (self.width, self.height), 255)
        draw = ImageDraw.Draw(image)

        # Get data
        from app.database import get_db
        db = get_db()
        stats = db.get_database_stats()

        # Check for following alerts first
        following_count = 0
        try:
            with db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT COUNT(*) FROM alerts
                    WHERE alert_type = 'following_detected'
                    AND status != 'dismissed'
                """)
                following_count = cursor.fetchone()[0]
        except:
            pass

        y = 2

        # CRITICAL: Following alert banner if present
        if following_count > 0:
            # Black background banner for following alert
            draw.rectangle([(0, y), (self.width, y+20)], fill=0)
            draw.text((5, y+2), f"!!! {following_count} FOLLOWING ALERT{'S' if following_count > 1 else ''} !!!",
                     font=self.font_medium, fill=255)
            y += 24
        else:
            # Time and status header
            now = datetime.now().strftime("%H:%M")
            draw.text((2, y), f"{now} PLUMBUS OK", font=self.font_small, fill=0)
            y += 14

        # Location (compact)
        try:
            from app.location import get_location_detector
            detector = get_location_detector()
            current_loc = detector.get_current_location()
            loc_name = current_loc.name[:18] if current_loc else "Unknown"
            draw.text((2, y), f"@{loc_name}", font=self.font_small, fill=0)
        except:
            draw.text((2, y), "@Unknown", font=self.font_small, fill=0)
        y += 14

        # WiFi mode (very short)
        try:
            from app.wifi_manager import get_wifi_manager
            wifi = get_wifi_manager()
            status = wifi.get_status()
            if status['strategy'] == 'dual_interface':
                mode = "DUAL"
            elif status['strategy'] == 'time_sliced':
                mode = "SLICED"
            else:
                mode = status['strategy'][:6].upper()
            draw.text((2, y), f"WiFi:{mode}", font=self.font_tiny, fill=0)
        except:
            pass
        y += 12

        # Compact stats - two columns
        draw.text((2, y), f"Dev:{stats['devices_count']}", font=self.font_tiny, fill=0)
        draw.text((130, y), f"Prb:{stats['probe_requests_count']}", font=self.font_tiny, fill=0)
        y += 12
        draw.text((2, y), f"Net:{stats['networks_count']}", font=self.font_tiny, fill=0)
        draw.text((130, y), f"Alr:{stats['alerts_count']}", font=self.font_tiny, fill=0)
        y += 12
        draw.text((2, y), f"Loc:{stats['locations_count']}", font=self.font_tiny, fill=0)

        # Bottom status line
        y = self.height - 12
        draw.line([(0, y-2), (self.width, y-2)], fill=0)
        draw.text((2, y), f"Scanning...", font=self.font_tiny, fill=0)
        draw.text((self.width-40, y), datetime.now().strftime("%m/%d"), font=self.font_tiny, fill=0)

        self._display_image(image)

    def _show_alerts_screen(self):
        """Display alerts - FOLLOWING alerts first, then others."""
        image = Image.new('1', (self.width, self.height), 255)
        draw = ImageDraw.Draw(image)

        # Get alerts - following first
        from app.database import get_db
        db = get_db()

        try:
            with db.get_connection() as conn:
                cursor = conn.cursor()
                # Get following alerts first, then others
                cursor.execute("""
                    SELECT alert_type, device_id, timestamp, status, location_id
                    FROM alerts
                    WHERE status != 'dismissed'
                    ORDER BY
                        CASE WHEN alert_type = 'following_detected' THEN 0 ELSE 1 END,
                        timestamp DESC
                    LIMIT 8
                """)
                alerts = cursor.fetchall()

            if alerts:
                y = 2
                for alert in alerts:
                    alert_type, device_id, timestamp, status, location_id = alert
                    time_str = datetime.fromtimestamp(timestamp).strftime("%m/%d %H:%M")
                    device_short = device_id[:6] if device_id else "???"

                    # FOLLOWING ALERTS get inverted display
                    if alert_type == 'following_detected':
                        # Black background for following
                        draw.rectangle([(0, y), (self.width, y+10)], fill=0)
                        draw.text((2, y), f"FOLLOW {device_short} {time_str}",
                                font=self.font_tiny, fill=255)
                    else:
                        # Regular alerts
                        type_short = alert_type[:8].replace('_', ' ').upper()
                        draw.text((2, y), f"{type_short[:6]} {device_short} {time_str}",
                                font=self.font_tiny, fill=0)

                    y += 11
                    if y > self.height - 15:
                        break

                # Footer
                draw.line([(0, self.height-12), (self.width, self.height-12)], fill=0)
                draw.text((2, self.height-10), f"{len(alerts)} alert(s)", font=self.font_tiny, fill=0)
            else:
                draw.text((2, 2), "ALERTS", font=self.font_medium, fill=0)
                draw.text((2, 50), "All clear!", font=self.font_small, fill=0)

        except Exception as e:
            draw.text((2, 2), "ALERTS", font=self.font_medium, fill=0)
            draw.text((2, 50), "Error", font=self.font_small, fill=0)

        self._display_image(image)

    def _show_networks_screen(self):
        """Display nearby networks - compact list."""
        image = Image.new('1', (self.width, self.height), 255)
        draw = ImageDraw.Draw(image)

        # Get recent network observations
        from app.database import get_db
        db = get_db()

        try:
            with db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT DISTINCT ssid, signal_strength
                    FROM network_observations
                    WHERE timestamp > strftime('%s', 'now') - 300
                    ORDER BY signal_strength DESC
                    LIMIT 10
                """)
                networks = cursor.fetchall()

            if networks:
                # Header
                draw.text((2, 2), f"NETWORKS ({len(networks)})", font=self.font_small, fill=0)
                draw.line([(0, 14), (self.width, 14)], fill=0)

                y = 16
                for ssid, signal in networks:
                    ssid_display = ssid[:22] if ssid else "<hidden>"
                    # Signal strength indicator
                    bars = "|||" if signal and signal > -60 else "||" if signal and signal > -75 else "|"
                    draw.text((2, y), f"{bars} {ssid_display}", font=self.font_tiny, fill=0)
                    y += 10

                    if y > self.height - 2:
                        break
            else:
                draw.text((2, 2), "NETWORKS", font=self.font_small, fill=0)
                draw.text((2, 50), "None visible", font=self.font_small, fill=0)

        except Exception as e:
            draw.text((2, 2), "NETWORKS", font=self.font_small, fill=0)
            draw.text((2, 50), "Error", font=self.font_small, fill=0)

        self._display_image(image)

    def _show_stats_screen(self):
        """Display statistics - compact grid."""
        image = Image.new('1', (self.width, self.height), 255)
        draw = ImageDraw.Draw(image)

        # Get stats
        from app.database import get_db
        db = get_db()
        stats = db.get_database_stats()

        # Title
        draw.text((2, 2), "STATS", font=self.font_small, fill=0)
        draw.line([(0, 14), (self.width, 14)], fill=0)

        # Compact two-column layout
        y = 18
        # Left column
        draw.text((2, y), f"Devices", font=self.font_tiny, fill=0)
        draw.text((60, y), f"{stats['devices_count']}", font=self.font_small, fill=0)
        y += 14

        draw.text((2, y), f"Locations", font=self.font_tiny, fill=0)
        draw.text((60, y), f"{stats['locations_count']}", font=self.font_small, fill=0)
        y += 14

        draw.text((2, y), f"Networks", font=self.font_tiny, fill=0)
        draw.text((60, y), f"{stats['networks_count']}", font=self.font_small, fill=0)
        y += 14

        draw.text((2, y), f"Probes", font=self.font_tiny, fill=0)
        draw.text((60, y), f"{stats['probe_requests_count']}", font=self.font_small, fill=0)
        y += 14

        draw.text((2, y), f"Alerts", font=self.font_tiny, fill=0)
        draw.text((60, y), f"{stats['alerts_count']}", font=self.font_small, fill=0)
        y += 14

        # Database size
        draw.line([(0, y+2), (self.width, y+2)], fill=0)
        y += 6
        draw.text((2, y), f"DB: {stats.get('database_size_mb', 0):.1f}MB", font=self.font_tiny, fill=0)

        self._display_image(image)

    def _show_location_screen(self):
        """Display current location - compact."""
        image = Image.new('1', (self.width, self.height), 255)
        draw = ImageDraw.Draw(image)

        try:
            from app.location import get_location_detector
            detector = get_location_detector()
            current_loc = detector.get_current_location()

            if current_loc:
                # Location name (big)
                draw.text((2, 2), "LOCATION", font=self.font_tiny, fill=0)
                draw.line([(0, 12), (self.width, 12)], fill=0)

                draw.text((2, 16), current_loc.name[:28], font=self.font_medium, fill=0)

                y = 36
                # Category
                cat = current_loc.category[:10].upper()
                draw.text((2, y), f"Type: {cat}", font=self.font_tiny, fill=0)
                y += 12

                # Networks
                draw.text((2, y), f"Networks: {current_loc.bssid_pool.size()}", font=self.font_tiny, fill=0)
                y += 12

                # Visits
                draw.text((2, y), f"Visits: {current_loc.detection_count}", font=self.font_tiny, fill=0)
                y += 12

                # Check for suspicious devices at this location
                from app.database import get_db
                db = get_db()
                with db.get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                        SELECT COUNT(DISTINCT device_id)
                        FROM device_locations
                        WHERE location_id = ?
                    """, (current_loc.location_id,))
                    device_count = cursor.fetchone()[0]

                draw.text((2, y), f"Devices seen: {device_count}", font=self.font_tiny, fill=0)
                y += 12

                # First/Last seen
                first = datetime.fromtimestamp(current_loc.first_detected).strftime("%m/%d")
                last = datetime.fromtimestamp(current_loc.last_detected).strftime("%m/%d %H:%M")
                draw.line([(0, y), (self.width, y)], fill=0)
                y += 2
                draw.text((2, y), f"1st:{first} Last:{last}", font=self.font_tiny, fill=0)

            else:
                draw.text((2, 2), "LOCATION", font=self.font_small, fill=0)
                draw.line([(0, 14), (self.width, 14)], fill=0)
                draw.text((2, 50), "Unknown", font=self.font_medium, fill=0)
                draw.text((2, 70), "Not enough WiFi", font=self.font_tiny, fill=0)
                draw.text((2, 82), "networks detected", font=self.font_tiny, fill=0)

        except Exception as e:
            logger.error(f"Error in location screen: {e}", exc_info=True)
            draw.text((2, 2), "LOCATION", font=self.font_small, fill=0)
            draw.text((2, 50), "Error", font=self.font_small, fill=0)

        self._display_image(image)

    def _display_image(self, image: 'Image'):
        """Display image on e-ink screen."""
        if not self.available or not self.epd:
            return

        try:
            # Rotate if needed
            if self.rotation != 0:
                image = image.rotate(self.rotation, expand=True)

            # Display on e-ink
            self.epd.display(self.epd.getbuffer(image))

        except Exception as e:
            logger.error(f"Error displaying image: {e}")

    def cycle_screen(self):
        """Cycle to next screen."""
        screens = list(DisplayScreen)
        current_index = screens.index(self.current_screen)
        next_index = (current_index + 1) % len(screens)
        self.current_screen = screens[next_index]
        logger.info(f"Switched to screen: {self.current_screen.value}")
        self.update(force=True)

    def set_screen(self, screen: DisplayScreen):
        """Set specific screen."""
        self.current_screen = screen
        self.update(force=True)

    def clear(self):
        """Clear the display."""
        if not self.available or not self.epd:
            return

        try:
            self.epd.Clear(0xFF)
        except Exception as e:
            logger.error(f"Error clearing display: {e}")

    def sleep(self):
        """Put display into sleep mode (low power)."""
        if not self.available or not self.epd:
            return

        try:
            self.epd.sleep()
            logger.info("E-Ink display in sleep mode")
        except Exception as e:
            logger.error(f"Error putting display to sleep: {e}")

    def get_status(self) -> Dict:
        """Get display status."""
        return {
            'available': self.available,
            'width': self.width,
            'height': self.height,
            'current_screen': self.current_screen.value if self.available else None,
            'last_refresh': self.last_refresh,
            'refresh_interval': self.refresh_interval,
            'rotation': self.rotation
        }


# Global instance
_eink_display: Optional[EInkDisplay] = None


def get_eink_display() -> EInkDisplay:
    """Get the global e-ink display instance."""
    global _eink_display
    if _eink_display is None:
        _eink_display = EInkDisplay()
    return _eink_display


def initialize_eink_display() -> bool:
    """Initialize the e-ink display."""
    display = get_eink_display()
    return display.initialize()
