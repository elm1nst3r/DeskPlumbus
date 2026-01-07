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
        """Display boot screen."""
        image = Image.new('1', (self.width, self.height), 255)  # White background
        draw = ImageDraw.Draw(image)

        # Title
        draw.text((10, 10), "WiFi Desk Plumbus", font=self.font_large, fill=0)

        # Version
        draw.text((10, 40), f"v{config.APP_VERSION}", font=self.font_small, fill=0)

        # Status
        draw.text((10, 60), "Initializing...", font=self.font_medium, fill=0)

        # Fun tagline
        draw.text((10, 90), "Everyone has one!", font=self.font_tiny, fill=0)

        # Border
        draw.rectangle([(0, 0), (self.width-1, self.height-1)], outline=0)

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
        """Display main status screen."""
        image = Image.new('1', (self.width, self.height), 255)
        draw = ImageDraw.Draw(image)

        # Get data
        from app.database import get_db
        db = get_db()
        stats = db.get_database_stats()

        # Header
        now = datetime.now().strftime("%H:%M:%S")
        draw.text((5, 2), f"Plumbus {now}", font=self.font_small, fill=0)
        draw.line([(0, 18), (self.width, 18)], fill=0)

        # WiFi status
        try:
            from app.wifi_manager import get_wifi_manager
            wifi = get_wifi_manager()
            status = wifi.get_status()
            strategy = status['strategy'].replace('_', ' ').upper()
            draw.text((5, 22), f"WiFi: {strategy[:10]}", font=self.font_small, fill=0)
        except:
            draw.text((5, 22), "WiFi: --", font=self.font_small, fill=0)

        # Location
        try:
            from app.location import get_location_detector
            detector = get_location_detector()
            current_loc = detector.get_current_location()
            loc_name = current_loc.name[:15] if current_loc else "Unknown"
            draw.text((5, 38), f"Loc: {loc_name}", font=self.font_small, fill=0)
        except:
            draw.text((5, 38), "Loc: Unknown", font=self.font_small, fill=0)

        # Stats
        y = 54
        draw.text((5, y), f"Devices: {stats['devices_count']}", font=self.font_small, fill=0)
        y += 16
        draw.text((5, y), f"Probes: {stats['probe_requests_count']}", font=self.font_small, fill=0)
        y += 16
        draw.text((5, y), f"Alerts: {stats['alerts_count']}", font=self.font_small, fill=0)

        # Border
        draw.rectangle([(0, 0), (self.width-1, self.height-1)], outline=0)

        self._display_image(image)

    def _show_alerts_screen(self):
        """Display recent alerts."""
        image = Image.new('1', (self.width, self.height), 255)
        draw = ImageDraw.Draw(image)

        # Header
        draw.text((5, 2), "Recent Alerts", font=self.font_medium, fill=0)
        draw.line([(0, 22), (self.width, 22)], fill=0)

        # Get alerts
        from app.database import get_db
        db = get_db()

        try:
            with db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT alert_type, device_id, timestamp, status
                    FROM alerts
                    ORDER BY timestamp DESC
                    LIMIT 5
                """)
                alerts = cursor.fetchall()

            if alerts:
                y = 28
                for alert in alerts:
                    alert_type, device_id, timestamp, status = alert
                    time_str = datetime.fromtimestamp(timestamp).strftime("%H:%M")
                    device_short = device_id[:8] if device_id else "Unknown"

                    # Alert type
                    draw.text((5, y), f"{time_str} {alert_type[:10]}", font=self.font_tiny, fill=0)
                    y += 12
                    draw.text((10, y), f"{device_short}", font=self.font_tiny, fill=0)
                    y += 14

                    if y > self.height - 10:
                        break
            else:
                draw.text((5, 50), "No recent alerts", font=self.font_small, fill=0)

        except Exception as e:
            draw.text((5, 50), "Error loading alerts", font=self.font_small, fill=0)

        # Border
        draw.rectangle([(0, 0), (self.width-1, self.height-1)], outline=0)

        self._display_image(image)

    def _show_networks_screen(self):
        """Display nearby networks."""
        image = Image.new('1', (self.width, self.height), 255)
        draw = ImageDraw.Draw(image)

        # Header
        draw.text((5, 2), "WiFi Networks", font=self.font_medium, fill=0)
        draw.line([(0, 22), (self.width, 22)], fill=0)

        # Get recent network observations
        from app.database import get_db
        db = get_db()

        try:
            with db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT DISTINCT ssid, bssid
                    FROM network_observations
                    WHERE timestamp > strftime('%s', 'now') - 300
                    ORDER BY timestamp DESC
                    LIMIT 6
                """)
                networks = cursor.fetchall()

            if networks:
                y = 28
                for ssid, bssid in networks:
                    ssid_display = ssid[:20] if ssid else "(hidden)"
                    draw.text((5, y), f"{ssid_display}", font=self.font_tiny, fill=0)
                    y += 14

                    if y > self.height - 10:
                        break
            else:
                draw.text((5, 50), "No networks visible", font=self.font_small, fill=0)

        except Exception as e:
            draw.text((5, 50), "Error loading networks", font=self.font_small, fill=0)

        # Border
        draw.rectangle([(0, 0), (self.width-1, self.height-1)], outline=0)

        self._display_image(image)

    def _show_stats_screen(self):
        """Display statistics."""
        image = Image.new('1', (self.width, self.height), 255)
        draw = ImageDraw.Draw(image)

        # Header
        draw.text((5, 2), "Statistics", font=self.font_medium, fill=0)
        draw.line([(0, 22), (self.width, 22)], fill=0)

        # Get stats
        from app.database import get_db
        db = get_db()
        stats = db.get_database_stats()

        y = 28
        draw.text((5, y), f"Devices: {stats['devices_count']}", font=self.font_small, fill=0)
        y += 16
        draw.text((5, y), f"Locations: {stats['locations_count']}", font=self.font_small, fill=0)
        y += 16
        draw.text((5, y), f"Networks: {stats['network_observations_count']}", font=self.font_small, fill=0)
        y += 16
        draw.text((5, y), f"Probes: {stats['probe_requests_count']}", font=self.font_small, fill=0)
        y += 16
        draw.text((5, y), f"Alerts: {stats['alerts_count']}", font=self.font_small, fill=0)

        # Border
        draw.rectangle([(0, 0), (self.width-1, self.height-1)], outline=0)

        self._display_image(image)

    def _show_location_screen(self):
        """Display current location details."""
        image = Image.new('1', (self.width, self.height), 255)
        draw = ImageDraw.Draw(image)

        # Header
        draw.text((5, 2), "Current Location", font=self.font_medium, fill=0)
        draw.line([(0, 22), (self.width, 22)], fill=0)

        try:
            from app.location import get_location_detector
            detector = get_location_detector()
            current_loc = detector.get_current_location()

            if current_loc:
                y = 28
                # Location name
                draw.text((5, y), current_loc.name[:25], font=self.font_small, fill=0)
                y += 18

                # Networks visible
                draw.text((5, y), f"Networks: {len(current_loc.bssid_pool)}", font=self.font_small, fill=0)
                y += 16

                # Visit count
                draw.text((5, y), f"Visits: {current_loc.detection_count}", font=self.font_small, fill=0)
                y += 16

                # First detected
                first_time = datetime.fromtimestamp(current_loc.first_detected).strftime("%m/%d %H:%M")
                draw.text((5, y), f"First: {first_time}", font=self.font_tiny, fill=0)
            else:
                draw.text((5, 50), "Location Unknown", font=self.font_small, fill=0)

        except Exception as e:
            draw.text((5, 50), "Error loading location", font=self.font_small, fill=0)

        # Border
        draw.rectangle([(0, 0), (self.width-1, self.height-1)], outline=0)

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
