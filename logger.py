import logging
import json
import os
from datetime import datetime, timezone
from config import Config


class SecurityLogger:
    """Structured security event logger."""

    def __init__(self, log_file=None):
        log_file = log_file or Config.SECURITY_LOG
        os.makedirs(os.path.dirname(log_file), exist_ok=True)

        self.logger = logging.getLogger('security')
        if not self.logger.handlers:
            self.logger.setLevel(logging.INFO)
            handler = logging.FileHandler(log_file)
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

    def _build_entry(self, event_type, user_id, details, severity, ip=None, ua=None):
        return {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'event_type': event_type,
            'user_id': user_id,
            'ip_address': ip,
            'user_agent': ua,
            'details': details,
            'severity': severity
        }

    def log_event(self, event_type, user_id=None, details=None, severity='INFO', ip_address=None, user_agent=None):
        entry = self._build_entry(event_type, user_id, details or {}, severity, ip_address, user_agent)
        msg = json.dumps(entry)
        level = severity.upper()
        if level == 'CRITICAL':
            self.logger.critical(msg)
        elif level == 'ERROR':
            self.logger.error(msg)
        elif level == 'WARNING':
            self.logger.warning(msg)
        else:
            self.logger.info(msg)


class AccessLogger:
    """HTTP access logger."""

    def __init__(self, log_file=None):
        log_file = log_file or Config.ACCESS_LOG
        os.makedirs(os.path.dirname(log_file), exist_ok=True)

        self.logger = logging.getLogger('access')
        if not self.logger.handlers:
            self.logger.setLevel(logging.INFO)
            handler = logging.FileHandler(log_file)
            formatter = logging.Formatter('%(asctime)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

    def log_request(self, method, path, status, user_id=None, ip=None):
        entry = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'method': method,
            'path': path,
            'status': status,
            'user_id': user_id,
            'ip': ip
        }
        self.logger.info(json.dumps(entry))


security_log = SecurityLogger()
access_log = AccessLogger()
