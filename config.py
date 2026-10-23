"""
SentinelSOC Configuration
Reads from environment variables / .env file.
"""
import os
from dotenv import load_dotenv

load_dotenv()

SECRET_KEY: str = os.environ.get("SECRET_KEY", "dev-secret-CHANGE-IN-PRODUCTION-abc123xyz")
FLASK_ENV: str = os.environ.get("FLASK_ENV", "development")
DATABASE_PATH: str = os.environ.get("DATABASE_PATH", "sentinelsoc.db")
MAX_UPLOAD_BYTES: int = int(os.environ.get("MAX_UPLOAD_BYTES", 5 * 1024 * 1024))  # 5 MB

# Detection rule defaults (all configurable via Settings page)
RULE_DEFAULTS = {
    "brute_force_threshold": 5,       # failed logins from same IP
    "brute_force_window_minutes": 5,
    "spray_threshold": 3,              # distinct accounts from same IP
    "spray_window_minutes": 10,
    "success_after_fail_threshold": 3, # fails before success
    "success_after_fail_window_minutes": 10,
    "lockout_spike_threshold": 5,      # lockouts in window
    "lockout_spike_window_minutes": 10,
    "multi_ip_threshold": 3,           # IPs targeting same account
    "multi_ip_window_minutes": 15,
}

DEBUG: bool = FLASK_ENV == "development"
