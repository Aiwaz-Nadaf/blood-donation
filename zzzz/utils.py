import os
import logging
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from flask import jsonify, session
from datetime import datetime
import re

# Configure logging
logging.basicConfig(
    level=os.getenv('LOG_LEVEL', 'INFO'),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename=os.getenv('LOG_FILE', 'app.log')
)

logger = logging.getLogger(__name__)

def hash_password(password):
    """Hash a password using Werkzeug's security functions."""
    return generate_password_hash(password)

def verify_password(hash_password, password):
    """Verify a password against its hash."""
    return check_password_hash(hash_password, password)

def validate_email(email):
    """Validate email format."""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))

def validate_phone(phone):
    """Validate phone number format."""
    pattern = r'^\+?1?\d{9,15}$'
    return bool(re.match(pattern, phone))

def validate_coordinates(latitude, longitude):
    """Validate geographical coordinates."""
    try:
        lat = float(latitude)
        lon = float(longitude)
        return -90 <= lat <= 90 and -180 <= lon <= 180
    except ValueError:
        return False

def admin_required(f):
    """Decorator to require admin authentication."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin' not in session:
            logger.warning('Unauthorized admin access attempt')
            return jsonify({'error': 'Admin authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function

def user_required(f):
    """Decorator to require user authentication."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            logger.warning('Unauthorized user access attempt')
            return jsonify({'error': 'User authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function

def log_error(error, context=None):
    """Log an error with context."""
    error_message = f"Error: {str(error)}"
    if context:
        error_message += f" Context: {context}"
    logger.error(error_message)

def format_datetime(dt):
    """Format datetime object to string."""
    if isinstance(dt, datetime):
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    return None

def sanitize_filename(filename):
    """Sanitize filename to prevent security issues."""
    # Remove any path traversal attempts
    filename = os.path.basename(filename)
    # Remove any non-alphanumeric characters except dots and hyphens
    filename = re.sub(r'[^a-zA-Z0-9.-]', '_', filename)
    return filename 