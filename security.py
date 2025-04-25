import re
from flask import current_app
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

def init_limiter(app):
    """Initialize rate limiter for the application"""
    return Limiter(
        app,
        key_func=get_remote_address,
        default_limits=[current_app.config['RATELIMIT_DEFAULT']]
    )

def validate_password_strength(password):
    """Validate password strength based on configuration"""
    config = current_app.config
    
    if len(password) < config['MIN_PASSWORD_LENGTH']:
        return False, "Password must be at least {} characters long".format(config['MIN_PASSWORD_LENGTH'])
    
    if config['REQUIRE_SPECIAL_CHARS'] and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character"
    
    if config['REQUIRE_NUMBERS'] and not re.search(r'\d', password):
        return False, "Password must contain at least one number"
    
    if config['REQUIRE_UPPERCASE'] and not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    
    if config['REQUIRE_LOWERCASE'] and not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    
    return True, "Password is valid"

def hash_password(password):
    """Hash a password using werkzeug's secure password hashing"""
    return generate_password_hash(password)

def verify_password(hashed_password, password):
    """Verify a password against its hash"""
    return check_password_hash(hashed_password, password)

def generate_secure_password(length=16):
    """Generate a secure random password"""
    import secrets
    import string
    
    alphabet = string.ascii_letters + string.digits + string.punctuation
    while True:
        password = ''.join(secrets.choice(alphabet) for i in range(length))
        if (any(c.islower() for c in password)
                and any(c.isupper() for c in password)
                and any(c.isdigit() for c in password)
                and any(c in string.punctuation for c in password)):
            break
    return password 