import os
import re
import uuid
import time
from werkzeug.utils import secure_filename
from config import Config
from storage import enc_storage, JSONStore
from logger import security_log

ALLOWED_EXTENSIONS = Config.ALLOWED_EXTENSIONS


def _load_docs():
    return JSONStore.load(Config.DOCUMENTS_FILE)

def _save_docs(docs):
    JSONStore.save(Config.DOCUMENTS_FILE, docs)

def _load_shares():
    return JSONStore.load(Config.SHARES_FILE)

def _save_shares(shares):
    JSONStore.save(Config.SHARES_FILE, shares)

def _load_versions():
    return JSONStore.load(Config.VERSIONS_FILE)

def _save_versions(versions):
    JSONStore.save(Config.VERSIONS_FILE, versions)


def safe_filename_check(filename):
    filename = secure_filename(filename)
    if not filename:
        raise ValueError("Invalid filename.")
    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
    if ext not in ALLOWED_EXTENSIONS:
        raise ValueError(f"File type '.{ext}' not allowed. Allowed: {', '.join(ALLOWED_EXTENSIONS)}")
    return filename, ext


def safe_file_path(filename, base_dir):
    full = os.path.join(base_dir, filename)
    if not os.path.abspath(full).startswith(os.path.abspath(base_dir)):
        raise ValueError("Path traversal detected.")
    return full


def upload_document(owner_id, owner_username, file_obj, original_filename, description=''):
    try:
        filename, ext = safe_filename_check(original_filename)
    except ValueError as e:
        return {'error': str(e)}

    file_bytes = file_obj.read()
    if len(file_bytes) > Config.MAX_CONTENT_LENGTH:
        return {'error': 'File too large (max 16MB).'}
    if len(file_bytes) == 0:
        return {'error': 'File is empty.'}

    doc_id = str(uuid.uuid4())
    stored_name = f"{doc_id}.enc"
    stored_path = safe_file_path(stored_name, Config.UPLOADS_DIR)

    encrypted = enc_storage.encrypt_bytes(file_bytes)
    with open(stored_path, 'wb') as f:
        f.write(encrypted)

    doc = {
        'id': doc_id,
        'owner_id': owner_id,
        'owner_username': owner_username,
        'original_filename': filename,
        'extension': ext,
        'description': description[:500],
        'size': len(file_bytes),
        'uploaded_at': time.time(),
        'version': 1,
        'stored_path': stored_path
    }

    versions = _load_versions()
    versions[doc_id] = [{
        'version': 1,
        'uploaded_at': doc['uploaded_at'],
        'uploaded_by': owner_username,
        'stored_path': stored_path
    }]
    _save_versions(versions)

    docs = _load_docs()
    docs[doc_id] = doc
    _save_docs(docs)

    security_log.log_event('DOCUMENT_UPLOADED', user_id=owner_id, details={'doc_id': doc_id, 'filename': filename})
    return {'success': True, 'doc_id': doc_id}


def download_document(doc_id, user_id, username):
    doc = get_document(doc_id)
    if not doc:
        return {'error': 'Document not found.'}
    if not can_access(doc_id, user_id, 'viewer'):
        security_log.log_event('ACCESS_DENIED', user_id=user_id, details={'doc_id': doc_id, 'action': 'download'}, severity='WARNING')
        return {'error': 'Access denied.'}

    with open(doc['stored_path'], 'rb') as f:
        encrypted = f.read()
    file_bytes = enc_storage.decrypt_bytes(encrypted)

    security_log.log_event('DATA_ACCESS', user_id=user_id, details={'resource': doc['original_filename'], 'doc_id': doc_id, 'action': 'download'})
    return {'success': True, 'data': file_bytes, 'filename': doc['original_filename'], 'extension': doc['extension']}


def update_document(doc_id, editor_id, editor_username, file_obj, original_filename):
    doc = get_document(doc_id)
    if not doc:
        return {'error': 'Document not found.'}
    if not can_access(doc_id, editor_id, 'editor'):
        return {'error': 'Access denied.'}

    try:
        filename, ext = safe_filename_check(original_filename)
    except ValueError as e:
        return {'error': str(e)}

    file_bytes = file_obj.read()
    if len(file_bytes) > Config.MAX_CONTENT_LENGTH:
        return {'error': 'File too large.'}

    new_version = doc['version'] + 1
    stored_name = f"{doc_id}_v{new_version}.enc"
    stored_path = safe_file_path(stored_name, Config.UPLOADS_DIR)
    encrypted = enc_storage.encrypt_bytes(file_bytes)
    with open(stored_path, 'wb') as f:
        f.write(encrypted)

    versions = _load_versions()
    versions.setdefault(doc_id, []).append({
        'version': new_version,
        'uploaded_at': time.time(),
        'uploaded_by': editor_username,
        'stored_path': stored_path
    })
    _save_versions(versions)

    docs = _load_docs()
    docs[doc_id]['version'] = new_version
    docs[doc_id]['stored_path'] = stored_path
    docs[doc_id]['original_filename'] = filename
    _save_docs(docs)

    security_log.log_event('DOCUMENT_UPDATED', user_id=editor_id, details={'doc_id': doc_id, 'new_version': new_version})
    return {'success': True, 'version': new_version}


def delete_document(doc_id, user_id, user_role):
    doc = get_document(doc_id)
    if not doc:
        return {'error': 'Document not found.'}
    if doc['owner_id'] != user_id and user_role != 'admin':
        security_log.log_event('ACCESS_DENIED', user_id=user_id, details={'doc_id': doc_id, 'action': 'delete'}, severity='WARNING')
        return {'error': 'Access denied.'}

    versions = _load_versions()
    for v in versions.get(doc_id, []):
        try:
            os.remove(v['stored_path'])
        except FileNotFoundError:
            pass
    versions.pop(doc_id, None)
    _save_versions(versions)

    docs = _load_docs()
    docs.pop(doc_id, None)
    _save_docs(docs)

    shares = _load_shares()
    shares.pop(doc_id, None)
    _save_shares(shares)

    security_log.log_event('DOCUMENT_DELETED', user_id=user_id, details={'doc_id': doc_id})
    return {'success': True}


def get_document(doc_id):
    return _load_docs().get(doc_id)


def get_user_documents(user_id):
    docs = _load_docs()
    shares = _load_shares()
    result = []
    for doc in docs.values():
        if doc['owner_id'] == user_id:
            d = dict(doc)
            d['access_role'] = 'owner'
            result.append(d)
        elif user_id in shares.get(doc['id'], {}):
            d = dict(doc)
            d['access_role'] = shares[doc['id']][user_id]
            result.append(d)
    return result


def get_all_documents():
    return list(_load_docs().values())


def share_document(doc_id, owner_id, target_username, role):
    from auth import get_user_by_username
    if role not in ('editor', 'viewer'):
        return {'error': 'Role must be editor or viewer.'}
    doc = get_document(doc_id)
    if not doc:
        return {'error': 'Document not found.'}
    if doc['owner_id'] != owner_id:
        return {'error': 'Only the owner can share this document.'}

    target = get_user_by_username(target_username)
    if not target:
        return {'error': 'User not found.'}
    if target['id'] == owner_id:
        return {'error': 'Cannot share with yourself.'}

    shares = _load_shares()
    shares.setdefault(doc_id, {})[target['id']] = role
    _save_shares(shares)

    security_log.log_event('DOCUMENT_SHARED', user_id=owner_id, details={'doc_id': doc_id, 'shared_with': target_username, 'role': role})
    return {'success': True}


def unshare_document(doc_id, owner_id, target_user_id):
    doc = get_document(doc_id)
    if not doc or doc['owner_id'] != owner_id:
        return {'error': 'Access denied.'}
    shares = _load_shares()
    if doc_id in shares:
        shares[doc_id].pop(target_user_id, None)
        _save_shares(shares)
    return {'success': True}


def get_document_shares(doc_id, owner_id):
    doc = get_document(doc_id)
    if not doc or doc['owner_id'] != owner_id:
        return {'error': 'Access denied.'}
    from auth import get_user_by_id
    shares_data = _load_shares().get(doc_id, {})
    result = []
    for uid, role in shares_data.items():
        user = get_user_by_id(uid)
        if user:
            result.append({'user_id': uid, 'username': user['username'], 'role': role})
    return result


def get_document_versions(doc_id, user_id):
    if not can_access(doc_id, user_id, 'viewer'):
        return {'error': 'Access denied.'}
    return _load_versions().get(doc_id, [])


def can_access(doc_id, user_id, required_role):
    from auth import get_user_by_id
    doc = get_document(doc_id)
    if not doc:
        return False
    user = get_user_by_id(user_id)
    if not user:
        return False
    if user.get('role') == 'admin':
        return True
    if doc['owner_id'] == user_id:
        return True
    shares = _load_shares().get(doc_id, {})
    actual_role = shares.get(user_id)
    if not actual_role:
        return False
    role_rank = {'viewer': 1, 'editor': 2}
    return role_rank.get(actual_role, 0) >= role_rank.get(required_role, 0)
