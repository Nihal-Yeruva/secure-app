import re
import time
import bcrypt
import html
import os
import uuid
from config import Config
from storage import enc_storage, JSONStore
from logger import security_log

#for the in-memory rate limit tracker
_rate_limits = {}


#validation

def validate_username(username):
    """3-20 chars, alphanumeric + underscore."""
    return bool(re.match(r'^\w{3,20}$', username))

def validate_email(email):
    return bool(re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email))

def validate_password_strength(password):
    if len(password) < 12:
        return False, "Password must be at least 12 characters."
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain an uppercase letter."
    if not re.search(r'[a-z]', password):
        return False, "Password must contain a lowercase letter."
    if not re.search(r'\d', password):
        return False, "Password must contain a number."
    if not re.search(r'[!@#$%^&*]', password):
        return False, "Password must contain a special character (!@#$%^&*)."
    return True, "OK"

def sanitize_input(value):
    """Escape HTML special characters."""
    if isinstance(value, str):
        return html.escape(value.strip())
    return value


#rate limiting

def check_rate_limit(ip):
    """Return True if IP is within rate limit."""
    now = time.time()
    window = now - Config.RATE_LIMIT_WINDOW
    attempts = _rate_limits.get(ip, [])
    attempts = [t for t in attempts if t > window]
    _rate_limits[ip] = attempts
    if len(attempts) >= Config.RATE_LIMIT_MAX:
        return False
    attempts.append(now)
    _rate_limits[ip] = attempts
    return True


#user storage helper methods

def _load_users():
    return enc_storage.load_encrypted(Config.USERS_FILE)

def _save_users(users):
    enc_storage.save_encrypted(Config.USERS_FILE, users)

def get_user_by_username(username):
    users = _load_users()
    return users.get(username)

def get_user_by_id(user_id):
    users = _load_users()
    for u in users.values():
        if u.get('id') == user_id:
            return u
    return None

def get_user_by_email(email):
    users = _load_users()
    for u in users.values():
        if u.get('email', '').lower() == email.lower():
            return u
    return None


#reg

def register_user(username, email, password, role='user'):
    username = sanitize_input(username)
    email = sanitize_input(email)

    if not validate_username(username):
        return {'error': 'Username must be 3-20 alphanumeric characters or underscores.'}
    if not validate_email(email):
        return {'error': 'Invalid email address.'}
    valid, msg = validate_password_strength(password)
    if not valid:
        return {'error': msg}
    if get_user_by_username(username):
        return {'error': 'Username already taken.'}
    if get_user_by_email(email):
        return {'error': 'Email already registered.'}

    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)

    user = {
        'id': str(uuid.uuid4()),
        'username': username,
        'email': email,
        'password_hash': hashed.decode('utf-8'),
        'created_at': time.time(),
        'role': role,
        'failed_attempts': 0,
        'locked_until': None
    }

    users = _load_users()
    users[username] = user
    _save_users(users)

    security_log.log_event('USER_REGISTERED', user_id=user['id'], details={'username': username})
    return {'success': True, 'user_id': user['id']}


#login

def authenticate_user(username, password, ip_address=None, user_agent=None):
    username = sanitize_input(username)

    #cehck rate limit
    if ip_address and not check_rate_limit(ip_address):
        security_log.log_event('RATE_LIMITED', details={'ip': ip_address}, severity='WARNING', ip_address=ip_address)
        return {'error': 'Too many login attempts. Please wait a minute.'}

    user = get_user_by_username(username)
    if not user:
        security_log.log_event('LOGIN_FAILED', details={'username': username,'reason': 'User not found'}, severity='WARNING', ip_address=ip_address, user_agent=user_agent)
        return {'error': 'Invalid username or password.'}

    #account lockout check
    if user.get('locked_until') and time.time() < user['locked_until']:
        remaining = int(user['locked_until'] - time.time())
        security_log.log_event('LOGIN_BLOCKED', user_id=user['id'], details={'reason': 'Account locked', 'remaining_seconds': remaining}, severity='WARNING', ip_address=ip_address)
        return {'error': f'Account locked. Try again in {remaining // 60 + 1} minutes.'}

    #check password
    if not bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
        user['failed_attempts'] = user.get('failed_attempts', 0) + 1
        if user['failed_attempts'] >= Config.MAX_LOGIN_ATTEMPTS:
            user['locked_until'] = time.time() + Config.LOCKOUT_DURATION
            security_log.log_event('ACCOUNT_LOCKED', user_id=user['id'], details={'reason': '5 failed login attempts'}, severity='ERROR', ip_address=ip_address)
        users = _load_users()
        users[username] = user
        _save_users(users)
        security_log.log_event('LOGIN_FAILED', user_id=user['id'], details={'username': username, 'reason': 'Invalid password', 'attempts': user['failed_attempts']}, severity='WARNING', ip_address=ip_address, user_agent=user_agent)
        return {'error': 'Invalid username or password.'}

    #reset failed attempts when success
    user['failed_attempts'] = 0
    user['locked_until'] = None
    users = _load_users()
    users[username] = user
    _save_users(users)

    security_log.log_event('LOGIN_SUCCESS', user_id=user['id'], details={'username': username}, ip_address=ip_address, user_agent=user_agent)
    return {'success': True, 'user': user}


def change_password(user_id, old_password, new_password, ip_address=None):
    user = get_user_by_id(user_id)
    if not user:
        return {'error': 'User not found.'}
    if not bcrypt.checkpw(old_password.encode(), user['password_hash'].encode()):
        security_log.log_event('PASSWORD_CHANGE_FAILED', user_id=user_id, details={'reason': 'Wrong current password'}, severity='WARNING', ip_address=ip_address)
        return {'error': 'Current password is incorrect.'}
    valid, msg = validate_password_strength(new_password)
    if not valid:
        return {'error': msg}

    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(new_password.encode(), salt)
    users = _load_users()
    users[user['username']]['password_hash'] = hashed.decode()
    _save_users(users)
    security_log.log_event('PASSWORD_CHANGED', user_id=user_id, ip_address=ip_address)
    return {'success': True}


def get_all_users():
    users = _load_users()
    #gets rid of password hashes before returning
    return [{k: v for k, v in u.items() if k != 'password_hash'} for u in users.values()]
