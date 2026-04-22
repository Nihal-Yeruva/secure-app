import os
import secrets

class Config:
    #secret key for Flask 
    SECRET_KEY = os.environ.get('SECRET_KEY', secrets.token_hex(32))
    
    #file paths
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    DATA_DIR = os.path.join(BASE_DIR, 'data')
    LOGS_DIR = os.path.join(BASE_DIR, 'logs')
    UPLOADS_DIR = os.path.join(DATA_DIR, 'uploads')
    
    #JSON data files
    USERS_FILE = os.path.join(DATA_DIR, 'users.json')
    SESSIONS_FILE = os.path.join(DATA_DIR, 'sessions.json')
    DOCUMENTS_FILE = os.path.join(DATA_DIR, 'documents.json')
    SHARES_FILE = os.path.join(DATA_DIR, 'shares.json')
    VERSIONS_FILE = os.path.join(DATA_DIR, 'versions.json')
    
    #log files
    SECURITY_LOG = os.path.join(LOGS_DIR, 'security.log')
    ACCESS_LOG = os.path.join(LOGS_DIR, 'access.log')
    
    #encryption key file
    ENCRYPTION_KEY_FILE = os.path.join(DATA_DIR, 'secret.key')
    
    #session settings
    SESSION_TIMEOUT = 1800  #30mins
    
    #rate limiting
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_DURATION = 900  #15mins
    RATE_LIMIT_WINDOW = 60  
    RATE_LIMIT_MAX = 10     
    
    #file upload
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB
    ALLOWED_EXTENSIONS = {'pdf', 'txt', 'docx', 'png', 'jpg', 'jpeg'}
    
    #environment
    ENV = os.environ.get('FLASK_ENV', 'development')
    DEBUG = ENV == 'development'

#confirm directories exist
for d in [Config.DATA_DIR, Config.LOGS_DIR, Config.UPLOADS_DIR]: os.makedirs(d, exist_ok=True)
