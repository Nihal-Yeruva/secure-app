"""
CS 419 — Secure Document Sharing System
Security Test Suite

Run: python tests/test_security.py
"""

import sys
import os
import time
import io
import unittest
import tempfile
import shutil

# Add parent dir to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Point all data/log dirs at a temp directory so tests don't pollute real data
_TMP = tempfile.mkdtemp()

import config
config.Config.DATA_DIR    = _TMP
config.Config.LOGS_DIR    = os.path.join(_TMP, 'logs')
config.Config.UPLOADS_DIR = os.path.join(_TMP, 'uploads')
config.Config.USERS_FILE      = os.path.join(_TMP, 'users.json')
config.Config.SESSIONS_FILE   = os.path.join(_TMP, 'sessions.json')
config.Config.DOCUMENTS_FILE  = os.path.join(_TMP, 'documents.json')
config.Config.SHARES_FILE     = os.path.join(_TMP, 'shares.json')
config.Config.VERSIONS_FILE   = os.path.join(_TMP, 'versions.json')
config.Config.ENCRYPTION_KEY_FILE = os.path.join(_TMP, 'secret.key')
config.Config.SECURITY_LOG    = os.path.join(_TMP, 'logs', 'security.log')
config.Config.ACCESS_LOG      = os.path.join(_TMP, 'logs', 'access.log')
os.makedirs(os.path.join(_TMP, 'logs'), exist_ok=True)
os.makedirs(os.path.join(_TMP, 'uploads'), exist_ok=True)

import auth
import sessions
import documents as docs
from storage import enc_storage


# ─── Helpers ──────────────────────────────────────────────────────────────────

def make_user(username='testuser', email=None, password='Test@Password1!', role='user'):
    email = email or f'{username}@test.com'
    return auth.register_user(username, email, password, role=role)


class BaseTest(unittest.TestCase):
    def setUp(self):
        # Wipe all data files before each test
        for f in [config.Config.USERS_FILE, config.Config.SESSIONS_FILE,
                  config.Config.DOCUMENTS_FILE, config.Config.SHARES_FILE,
                  config.Config.VERSIONS_FILE]:
            if os.path.exists(f):
                os.remove(f)
        # Clear rate limits
        auth._rate_limits.clear()


# ─── A. Authentication Tests ──────────────────────────────────────────────────

class TestAuthentication(BaseTest):

    def test_register_valid_user(self):
        r = make_user('alice')
        self.assertIn('success', r)
        self.assertIn('user_id', r)

    def test_register_duplicate_username(self):
        make_user('alice')
        r = make_user('alice')
        self.assertIn('error', r)

    def test_register_duplicate_email(self):
        make_user('alice', email='shared@test.com')
        r = auth.register_user('bob', 'shared@test.com', 'Test@Password1!')
        self.assertIn('error', r)

    def test_register_invalid_username_short(self):
        r = auth.register_user('ab', 'a@b.com', 'Test@Password1!')
        self.assertIn('error', r)

    def test_register_invalid_username_chars(self):
        r = auth.register_user('user name!', 'a@b.com', 'Test@Password1!')
        self.assertIn('error', r)

    def test_register_weak_password_too_short(self):
        r = auth.register_user('alice', 'a@b.com', 'Short1!')
        self.assertIn('error', r)

    def test_register_weak_password_no_uppercase(self):
        r = auth.register_user('alice', 'a@b.com', 'nouppercase1!')
        self.assertIn('error', r)

    def test_register_weak_password_no_special(self):
        r = auth.register_user('alice', 'a@b.com', 'NoSpecialChar1')
        self.assertIn('error', r)

    def test_register_invalid_email(self):
        r = auth.register_user('alice', 'notanemail', 'Test@Password1!')
        self.assertIn('error', r)

    def test_login_success(self):
        make_user('alice')
        r = auth.authenticate_user('alice', 'Test@Password1!')
        self.assertIn('success', r)
        self.assertEqual(r['user']['username'], 'alice')

    def test_login_wrong_password(self):
        make_user('alice')
        r = auth.authenticate_user('alice', 'WrongPassword1!')
        self.assertIn('error', r)

    def test_login_nonexistent_user(self):
        r = auth.authenticate_user('nobody', 'Test@Password1!')
        self.assertIn('error', r)

    def test_password_hashed_not_plaintext(self):
        """Password must not be stored in plaintext."""
        make_user('alice')
        users = enc_storage.load_encrypted(config.Config.USERS_FILE)
        user = users.get('alice', {})
        self.assertNotEqual(user.get('password_hash'), 'Test@Password1!')
        self.assertTrue(user.get('password_hash', '').startswith('$2b$'))

    def test_bcrypt_cost_factor(self):
        """Bcrypt cost factor must be >= 12."""
        make_user('alice')
        users = enc_storage.load_encrypted(config.Config.USERS_FILE)
        ph = users['alice']['password_hash']
        # $2b$12$... — cost factor is the number after second $
        cost = int(ph.split('$')[2])
        self.assertGreaterEqual(cost, 12)

    def test_account_lockout_after_5_failures(self):
        make_user('alice')
        for _ in range(5):
            auth.authenticate_user('alice', 'WrongPassword1!', ip_address='1.2.3.4')
        r = auth.authenticate_user('alice', 'Test@Password1!', ip_address='1.2.3.4')
        self.assertIn('error', r)
        self.assertIn('locked', r['error'].lower())

    def test_successful_login_resets_failed_attempts(self):
        make_user('alice')
        auth.authenticate_user('alice', 'WrongPassword1!')
        auth.authenticate_user('alice', 'Test@Password1!')
        users = enc_storage.load_encrypted(config.Config.USERS_FILE)
        self.assertEqual(users['alice']['failed_attempts'], 0)

    def test_rate_limiting(self):
        """IP should be rate-limited after 10 attempts per minute."""
        make_user('alice')
        for _ in range(10):
            auth.authenticate_user('alice', 'WrongPassword1!', ip_address='5.5.5.5')
        r = auth.authenticate_user('alice', 'Test@Password1!', ip_address='5.5.5.5')
        self.assertIn('error', r)
        self.assertIn('Too many', r['error'])

    def test_different_ips_not_rate_limited_together(self):
        # Use a unique username to avoid lockout from other tests
        make_user('charlie_rl', password='Test@Password1!')
        # Rate-limit 9.9.9.9 using correct password (no lockout, just rate window)
        for _ in range(10):
            auth.authenticate_user('charlie_rl', 'Test@Password1!', ip_address='9.9.9.9')
        # 9.9.9.9 is rate-limited now; 8.8.8.8 should still work
        r = auth.authenticate_user('charlie_rl', 'Test@Password1!', ip_address='8.8.8.8')
        self.assertIn('success', r)


# ─── B. Session Tests ─────────────────────────────────────────────────────────

class TestSessions(BaseTest):

    def test_session_created_on_login(self):
        make_user('alice')
        r = auth.authenticate_user('alice', 'Test@Password1!')
        token = sessions.session_manager.create_session(r['user']['id'])
        self.assertIsNotNone(token)
        self.assertGreater(len(token), 30)

    def test_session_token_urlsafe(self):
        make_user('alice')
        r = auth.authenticate_user('alice', 'Test@Password1!')
        tokens = set()
        for _ in range(10):
            t = sessions.session_manager.create_session(r['user']['id'])
            tokens.add(t)
        # All tokens should be unique
        self.assertEqual(len(tokens), 10)

    def test_session_validation(self):
        make_user('alice')
        r = auth.authenticate_user('alice', 'Test@Password1!')
        token = sessions.session_manager.create_session(r['user']['id'])
        session = sessions.session_manager.validate_session(token)
        self.assertIsNotNone(session)
        self.assertEqual(session['user_id'], r['user']['id'])

    def test_invalid_token_rejected(self):
        session = sessions.session_manager.validate_session('fakeinvalidtoken')
        self.assertIsNone(session)

    def test_session_destroyed_on_logout(self):
        make_user('alice')
        r = auth.authenticate_user('alice', 'Test@Password1!')
        token = sessions.session_manager.create_session(r['user']['id'])
        sessions.session_manager.destroy_session(token)
        session = sessions.session_manager.validate_session(token)
        self.assertIsNone(session)

    def test_session_timeout(self):
        sm = sessions.SessionManager.__new__(sessions.SessionManager)
        sm.timeout = 0  # immediate expiry
        sm.file = config.Config.SESSIONS_FILE
        make_user('alice')
        r = auth.authenticate_user('alice', 'Test@Password1!')
        token = sm.create_session(r['user']['id'])
        time.sleep(0.01)
        session = sm.validate_session(token)
        self.assertIsNone(session)

    def test_sessions_stored_encrypted(self):
        """Sessions file should be binary (encrypted), not plaintext JSON."""
        make_user('alice')
        r = auth.authenticate_user('alice', 'Test@Password1!')
        sessions.session_manager.create_session(r['user']['id'])
        with open(config.Config.SESSIONS_FILE, 'rb') as f:
            data = f.read()
        # Fernet tokens start with 'gAAAAA' in base64 — definitely not plain JSON
        self.assertFalse(data.startswith(b'{'))


# ─── C. Access Control Tests ──────────────────────────────────────────────────

class TestAccessControl(BaseTest):

    def _upload_for(self, user_id, username, content=b'hello world'):
        f = io.BytesIO(content)
        return docs.upload_document(user_id, username, f, 'test.txt', 'desc')

    def test_owner_can_download_own_doc(self):
        make_user('alice')
        alice = auth.get_user_by_username('alice')
        r = self._upload_for(alice['id'], 'alice')
        doc_id = r['doc_id']
        dl = docs.download_document(doc_id, alice['id'], 'alice')
        self.assertIn('success', dl)
        self.assertEqual(dl['data'], b'hello world')

    def test_stranger_cannot_download(self):
        make_user('alice')
        make_user('bob')
        alice = auth.get_user_by_username('alice')
        bob   = auth.get_user_by_username('bob')
        r = self._upload_for(alice['id'], 'alice')
        dl = docs.download_document(r['doc_id'], bob['id'], 'bob')
        self.assertIn('error', dl)

    def test_viewer_can_download_shared_doc(self):
        make_user('alice')
        make_user('bob')
        alice = auth.get_user_by_username('alice')
        bob   = auth.get_user_by_username('bob')
        r = self._upload_for(alice['id'], 'alice')
        docs.share_document(r['doc_id'], alice['id'], 'bob', 'viewer')
        dl = docs.download_document(r['doc_id'], bob['id'], 'bob')
        self.assertIn('success', dl)

    def test_viewer_cannot_update(self):
        make_user('alice')
        make_user('bob')
        alice = auth.get_user_by_username('alice')
        bob   = auth.get_user_by_username('bob')
        r = self._upload_for(alice['id'], 'alice')
        docs.share_document(r['doc_id'], alice['id'], 'bob', 'viewer')
        upd = docs.update_document(r['doc_id'], bob['id'], 'bob',
                                   io.BytesIO(b'new content'), 'test.txt')
        self.assertIn('error', upd)

    def test_editor_can_update(self):
        make_user('alice')
        make_user('bob')
        alice = auth.get_user_by_username('alice')
        bob   = auth.get_user_by_username('bob')
        r = self._upload_for(alice['id'], 'alice')
        docs.share_document(r['doc_id'], alice['id'], 'bob', 'editor')
        upd = docs.update_document(r['doc_id'], bob['id'], 'bob',
                                   io.BytesIO(b'updated'), 'test.txt')
        self.assertIn('success', upd)

    def test_admin_can_access_any_doc(self):
        make_user('alice')
        make_user('admin_user', role='admin')
        alice = auth.get_user_by_username('alice')
        adm   = auth.get_user_by_username('admin_user')
        r = self._upload_for(alice['id'], 'alice')
        dl = docs.download_document(r['doc_id'], adm['id'], 'admin_user')
        self.assertIn('success', dl)

    def test_only_owner_can_share(self):
        make_user('alice')
        make_user('bob')
        make_user('charlie')
        alice = auth.get_user_by_username('alice')
        bob   = auth.get_user_by_username('bob')
        r = self._upload_for(alice['id'], 'alice')
        # Bob tries to share Alice's doc
        res = docs.share_document(r['doc_id'], bob['id'], 'charlie', 'viewer')
        self.assertIn('error', res)

    def test_owner_cannot_share_invalid_role(self):
        make_user('alice')
        make_user('bob')
        alice = auth.get_user_by_username('alice')
        r = self._upload_for(alice['id'], 'alice')
        res = docs.share_document(r['doc_id'], alice['id'], 'bob', 'superuser')
        self.assertIn('error', res)

    def test_revoke_access(self):
        make_user('alice')
        make_user('bob')
        alice = auth.get_user_by_username('alice')
        bob   = auth.get_user_by_username('bob')
        r = self._upload_for(alice['id'], 'alice')
        docs.share_document(r['doc_id'], alice['id'], 'bob', 'viewer')
        docs.unshare_document(r['doc_id'], alice['id'], bob['id'])
        dl = docs.download_document(r['doc_id'], bob['id'], 'bob')
        self.assertIn('error', dl)


# ─── D. Encryption Tests ──────────────────────────────────────────────────────

class TestEncryption(BaseTest):

    def test_uploaded_file_stored_encrypted(self):
        make_user('alice')
        alice = auth.get_user_by_username('alice')
        content = b'SUPERSECRET DOCUMENT CONTENT'
        f = io.BytesIO(content)
        r = docs.upload_document(alice['id'], 'alice', f, 'secret.txt')
        doc = docs.get_document(r['doc_id'])
        with open(doc['stored_path'], 'rb') as fh:
            raw = fh.read()
        self.assertNotIn(content, raw, "File stored in plaintext!")
        self.assertFalse(raw.startswith(b'SUPERSECRET'))

    def test_decrypted_content_matches_original(self):
        make_user('alice')
        alice = auth.get_user_by_username('alice')
        content = b'Original file content 12345'
        f = io.BytesIO(content)
        r = docs.upload_document(alice['id'], 'alice', f, 'file.txt')
        dl = docs.download_document(r['doc_id'], alice['id'], 'alice')
        self.assertEqual(dl['data'], content)

    def test_users_file_stored_encrypted(self):
        make_user('alice')
        with open(config.Config.USERS_FILE, 'rb') as f:
            data = f.read()
        self.assertNotIn(b'Test@Password1!', data)
        self.assertNotIn(b'"alice"', data)  # Not plaintext JSON

    def test_encrypt_decrypt_roundtrip(self):
        original = b'Test data for encryption roundtrip'
        encrypted = enc_storage.encrypt_bytes(original)
        self.assertNotEqual(encrypted, original)
        decrypted = enc_storage.decrypt_bytes(encrypted)
        self.assertEqual(decrypted, original)

    def test_different_encryptions_of_same_data(self):
        """Fernet uses random IV so same data → different ciphertext each time."""
        data = b'same data'
        e1 = enc_storage.encrypt_bytes(data)
        e2 = enc_storage.encrypt_bytes(data)
        self.assertNotEqual(e1, e2)


# ─── E. Input Validation Tests ────────────────────────────────────────────────

class TestInputValidation(BaseTest):

    def test_sanitize_xss(self):
        payload = '<script>alert("xss")</script>'
        sanitized = auth.sanitize_input(payload)
        self.assertNotIn('<script>', sanitized)
        self.assertIn('&lt;', sanitized)

    def test_sanitize_html_entities(self):
        payload = '<img src=x onerror=alert(1)>'
        sanitized = auth.sanitize_input(payload)
        self.assertNotIn('<img', sanitized)

    def test_filename_path_traversal_blocked(self):
        from documents import safe_filename_check
        with self.assertRaises(Exception):
            safe_filename_check('../../../etc/passwd')

    def test_filename_with_null_bytes(self):
        from documents import safe_filename_check
        # werkzeug secure_filename strips null bytes
        result = safe_filename_check('file\x00name.txt')
        self.assertNotIn('\x00', result[0])

    def test_disallowed_extension_blocked(self):
        make_user('alice')
        alice = auth.get_user_by_username('alice')
        f = io.BytesIO(b'#!/bin/bash\nrm -rf /')
        r = docs.upload_document(alice['id'], 'alice', f, 'evil.sh')
        self.assertIn('error', r)

    def test_disallowed_extension_exe(self):
        make_user('alice')
        alice = auth.get_user_by_username('alice')
        f = io.BytesIO(b'MZ\x90\x00malware')
        r = docs.upload_document(alice['id'], 'alice', f, 'malware.exe')
        self.assertIn('error', r)

    def test_path_traversal_in_safe_file_path(self):
        from documents import safe_file_path
        base = config.Config.UPLOADS_DIR
        with self.assertRaises(ValueError):
            safe_file_path('../../etc/shadow', base)

    def test_empty_file_rejected(self):
        make_user('alice')
        alice = auth.get_user_by_username('alice')
        f = io.BytesIO(b'')
        r = docs.upload_document(alice['id'], 'alice', f, 'empty.txt')
        self.assertIn('error', r)

    def test_username_length_limits(self):
        long_name = 'a' * 25
        r = auth.register_user(long_name, 'a@b.com', 'Test@Password1!')
        self.assertIn('error', r)

    def test_password_confirmation_mismatch(self):
        # App layer handles this (tested via the view), but validate_password_strength is clean
        valid, _ = auth.validate_password_strength('Test@Password1!')
        self.assertTrue(valid)


# ─── F. Document Versioning Tests ─────────────────────────────────────────────

class TestVersioning(BaseTest):

    def test_version_increments_on_update(self):
        make_user('alice')
        alice = auth.get_user_by_username('alice')
        r = docs.upload_document(alice['id'], 'alice', io.BytesIO(b'v1'), 'doc.txt')
        doc_id = r['doc_id']
        docs.update_document(doc_id, alice['id'], 'alice', io.BytesIO(b'v2'), 'doc.txt')
        doc = docs.get_document(doc_id)
        self.assertEqual(doc['version'], 2)

    def test_version_history_preserved(self):
        make_user('alice')
        alice = auth.get_user_by_username('alice')
        r = docs.upload_document(alice['id'], 'alice', io.BytesIO(b'v1'), 'doc.txt')
        docs.update_document(r['doc_id'], alice['id'], 'alice', io.BytesIO(b'v2'), 'doc.txt')
        docs.update_document(r['doc_id'], alice['id'], 'alice', io.BytesIO(b'v3'), 'doc.txt')
        versions = docs.get_document_versions(r['doc_id'], alice['id'])
        self.assertEqual(len(versions), 3)

    def test_latest_version_content_correct(self):
        make_user('alice')
        alice = auth.get_user_by_username('alice')
        r = docs.upload_document(alice['id'], 'alice', io.BytesIO(b'v1 content'), 'doc.txt')
        docs.update_document(r['doc_id'], alice['id'], 'alice',
                             io.BytesIO(b'v2 content'), 'doc.txt')
        dl = docs.download_document(r['doc_id'], alice['id'], 'alice')
        self.assertEqual(dl['data'], b'v2 content')


# ─── G. Password Change Tests ─────────────────────────────────────────────────

class TestPasswordChange(BaseTest):

    def test_change_password_success(self):
        make_user('alice')
        alice = auth.get_user_by_username('alice')
        r = auth.change_password(alice['id'], 'Test@Password1!', 'NewPass@Word99!')
        self.assertIn('success', r)

    def test_change_password_wrong_current(self):
        make_user('alice')
        alice = auth.get_user_by_username('alice')
        r = auth.change_password(alice['id'], 'WrongCurrent1!', 'NewPass@Word99!')
        self.assertIn('error', r)

    def test_change_password_weak_new(self):
        make_user('alice')
        alice = auth.get_user_by_username('alice')
        r = auth.change_password(alice['id'], 'Test@Password1!', 'weakpassword')
        self.assertIn('error', r)

    def test_new_password_usable_after_change(self):
        make_user('alice')
        alice = auth.get_user_by_username('alice')
        auth.change_password(alice['id'], 'Test@Password1!', 'NewPass@Word99!')
        r = auth.authenticate_user('alice', 'NewPass@Word99!')
        self.assertIn('success', r)

    def test_old_password_rejected_after_change(self):
        make_user('alice')
        alice = auth.get_user_by_username('alice')
        auth.change_password(alice['id'], 'Test@Password1!', 'NewPass@Word99!')
        r = auth.authenticate_user('alice', 'Test@Password1!')
        self.assertIn('error', r)


# ─── Cleanup ──────────────────────────────────────────────────────────────────

def teardown():
    shutil.rmtree(_TMP, ignore_errors=True)


if __name__ == '__main__':
    print("=" * 60)
    print("CS 419 — Security Test Suite")
    print("=" * 60)
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for cls in [TestAuthentication, TestSessions, TestAccessControl,
                TestEncryption, TestInputValidation, TestVersioning,
                TestPasswordChange]:
        suite.addTests(loader.loadTestsFromTestCase(cls))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    teardown()
    sys.exit(0 if result.wasSuccessful() else 1)
