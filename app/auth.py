"""
WiFi Desk Plumbus - Authentication Module

Simple password-based authentication for web interface (Phase 6).

This provides basic protection for the web dashboard. For production use,
consider implementing:
- Flask-Login with user database
- HTTPS/TLS encryption
- Two-factor authentication
- API token authentication
"""

import logging
from functools import wraps
from flask import session, redirect, url_for, request, render_template_string
import config

logger = logging.getLogger(__name__)

# Enable authentication (set to False to disable)
AUTH_ENABLED = True

# Simple login page template
LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WiFi Desk Plumbus - Login</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            padding: 20px;
        }

        .login-container {
            background: white;
            border-radius: 10px;
            padding: 40px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.2);
            max-width: 400px;
            width: 100%;
        }

        .login-header {
            text-align: center;
            margin-bottom: 30px;
        }

        .login-header h1 {
            color: #667eea;
            font-size: 2em;
            margin-bottom: 10px;
        }

        .login-header p {
            color: #666;
            font-size: 0.9em;
        }

        .form-group {
            margin-bottom: 20px;
        }

        .form-group label {
            display: block;
            margin-bottom: 8px;
            color: #333;
            font-weight: 500;
        }

        .form-group input {
            width: 100%;
            padding: 12px;
            border: 2px solid #e0e0e0;
            border-radius: 5px;
            font-size: 1em;
            transition: border-color 0.3s;
        }

        .form-group input:focus {
            outline: none;
            border-color: #667eea;
        }

        .login-button {
            width: 100%;
            padding: 12px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 5px;
            font-size: 1em;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.3s;
        }

        .login-button:hover {
            background: #5568d3;
        }

        .error-message {
            background: #fee;
            border: 1px solid #fcc;
            color: #c33;
            padding: 12px;
            border-radius: 5px;
            margin-bottom: 20px;
            font-size: 0.9em;
        }

        .plumbus-icon {
            font-size: 3em;
            margin-bottom: 10px;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="login-header">
            <div class="plumbus-icon">🛸</div>
            <h1>WiFi Desk Plumbus</h1>
            <p>Everyone has one... do you have the password?</p>
        </div>

        {% if error %}
        <div class="error-message">
            {{ error }}
        </div>
        {% endif %}

        <form method="POST" action="{{ url_for('login') }}">
            <div class="form-group">
                <label for="password">Password</label>
                <input
                    type="password"
                    id="password"
                    name="password"
                    placeholder="Enter password"
                    required
                    autofocus
                >
            </div>

            <button type="submit" class="login-button">
                Access Plumbus Sentinel
            </button>
        </form>

        <p style="margin-top: 20px; text-align: center; color: #999; font-size: 0.85em;">
            Default password: <code>plumbus123</code><br>
            (Change in .env file)
        </p>
    </div>
</body>
</html>
"""


def check_password(password: str) -> bool:
    """
    Check if provided password is correct.

    Args:
        password: Password to check

    Returns:
        True if password is correct, False otherwise
    """
    expected_password = config.WEB_PASSWORD
    return password == expected_password


def login_required(f):
    """
    Decorator to require authentication for routes.

    Usage:
        @app.route('/protected')
        @login_required
        def protected_route():
            return 'This is protected'
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Skip authentication if disabled
        if not AUTH_ENABLED:
            return f(*args, **kwargs)

        # Check if user is logged in
        if not session.get('authenticated'):
            # Store the original URL to redirect back after login
            session['next_url'] = request.url
            return redirect(url_for('login'))

        return f(*args, **kwargs)

    return decorated_function


def register_auth_routes(app):
    """
    Register authentication routes.

    Args:
        app: Flask application instance
    """

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        """Handle login page and authentication."""
        # Skip if already authenticated
        if session.get('authenticated'):
            return redirect(url_for('index'))

        error = None

        if request.method == 'POST':
            password = request.form.get('password', '')

            if check_password(password):
                # Set session
                session['authenticated'] = True
                logger.info("User authenticated successfully")

                # Redirect to original URL or index
                next_url = session.pop('next_url', None)
                return redirect(next_url or url_for('index'))
            else:
                error = "Incorrect password. Please try again."
                logger.warning("Failed login attempt")

        return render_template_string(LOGIN_TEMPLATE, error=error)

    @app.route('/logout')
    def logout():
        """Handle logout."""
        session.pop('authenticated', None)
        logger.info("User logged out")
        return redirect(url_for('login'))

    logger.info("Authentication routes registered")


def init_auth(app):
    """
    Initialize authentication for the Flask app.

    Args:
        app: Flask application instance
    """
    # Ensure secret key is set
    if not app.config.get('SECRET_KEY'):
        logger.error("SECRET_KEY not set! Sessions will not work properly.")
        app.config['SECRET_KEY'] = 'insecure-default-key-change-this'

    # Set session to be permanent (30 days by default)
    app.config['PERMANENT_SESSION_LIFETIME'] = 2592000  # 30 days in seconds

    # Register auth routes
    register_auth_routes(app)

    if AUTH_ENABLED:
        logger.info("Authentication enabled")
    else:
        logger.info("Authentication disabled")


# Test authentication
if __name__ == '__main__':
    print("Testing Authentication Module...")

    # Test password check
    test_password = "plumbus123"
    result = check_password(test_password)
    print(f"Password check for '{test_password}': {result}")

    print("\nAuthentication module ready!")
    print(f"AUTH_ENABLED: {AUTH_ENABLED}")
