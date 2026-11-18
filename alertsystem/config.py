import os


class Config:
    # -----------------------------------------------------------------
    # Flask secret key
    # -----------------------------------------------------------------
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production-!@#$%')

    # -----------------------------------------------------------------
    # MySQL connection settings
    # -----------------------------------------------------------------
    DB_HOST = os.environ.get('DB_HOST', 'localhost')
    DB_PORT = int(os.environ.get('DB_PORT', 3306))
    DB_NAME = os.environ.get('DB_NAME', 'cyberattack_detection')
    DB_USER = os.environ.get('DB_USER', 'root')
    DB_PASSWORD = os.environ.get('DB_PASSWORD', '')

    # -----------------------------------------------------------------
    # Session settings
    # -----------------------------------------------------------------
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = int(os.environ.get('SESSION_LIFETIME_SECONDS', 3600))  # 1 hour

    # -----------------------------------------------------------------
    # Detection thresholds
    # -----------------------------------------------------------------
    # Port-scan detection
    PORT_SCAN_THRESHOLD = int(os.environ.get('PORT_SCAN_THRESHOLD', 10))   # unique ports per window
    PORT_SCAN_WINDOW    = int(os.environ.get('PORT_SCAN_WINDOW', 60))       # seconds

    # Brute-force detection
    BRUTE_FORCE_THRESHOLD = int(os.environ.get('BRUTE_FORCE_THRESHOLD', 5))  # failed attempts per window
    BRUTE_FORCE_WINDOW    = int(os.environ.get('BRUTE_FORCE_WINDOW', 60))    # seconds

    # DoS / DDoS detection
    DOS_THRESHOLD = int(os.environ.get('DOS_THRESHOLD', 100))  # packets/requests per window
    DOS_WINDOW    = int(os.environ.get('DOS_WINDOW', 10))       # seconds

    # Suspicious IP detection
    SUSPICIOUS_IP_THRESHOLD = int(os.environ.get('SUSPICIOUS_IP_THRESHOLD', 50))  # events per minute
