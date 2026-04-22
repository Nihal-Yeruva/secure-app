import secrets
import time
from config import Config
from storage import enc_storage
from logger import security_log


class SessionManager:
    """Secure server-side session management."""

    def __init__(self):
        self.timeout = Config.SESSION_TIMEOUT
        self.file = Config.SESSIONS_FILE

    def _load(self):
        return enc_storage.load_encrypted(self.file)

    def _save(self, sessions):
        enc_storage.save_encrypted(self.file, sessions)

    def create_session(self, user_id, ip_address=None, user_agent=None):
        token = secrets.token_urlsafe(32)
        session = {
            'token': token,
            'user_id': user_id,
            'created_at': time.time(),
            'last_activity': time.time(),
            'ip_address': ip_address,
            'user_agent': user_agent
        }
        sessions = self._load()
        #cleans expired sessions on create
        sessions = {k: v for k, v in sessions.items() if time.time() - v['last_activity'] <= self.timeout}
        sessions[token] = session
        self._save(sessions)
        security_log.log_event('SESSION_CREATED', user_id=user_id, ip_address=ip_address, user_agent=user_agent)
        return token

    def validate_session(self, token):
        if not token:
            return None
        sessions = self._load()
        session = sessions.get(token)
        if not session:
            return None
        if time.time() - session['last_activity'] > self.timeout:
            self.destroy_session(token)
            return None
        #updates last activity
        session['last_activity'] = time.time()
        sessions[token] = session
        self._save(sessions)
        return session

    def destroy_session(self, token, user_id=None):
        sessions = self._load()
        if token in sessions:
            uid = user_id or sessions[token].get('user_id')
            del sessions[token]
            self._save(sessions)
            security_log.log_event('SESSION_DESTROYED', user_id=uid)

    def destroy_all_user_sessions(self, user_id):
        sessions = self._load()
        sessions = {k: v for k, v in sessions.items() if v['user_id'] != user_id}
        self._save(sessions)


session_manager = SessionManager()
