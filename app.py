import os
import io
import html
import mimetypes

from functools import wraps
from flask import (Flask, request, redirect, url_for, render_template, make_response, g, jsonify, send_file, abort, flash)
from config import Config
from auth import (register_user, authenticate_user, get_user_by_id, get_all_users, sanitize_input, change_password)
from sessions import session_manager
from documents import (upload_document, download_document, update_document, delete_document, get_document, get_user_documents, get_all_documents, share_document, unshare_document, get_document_shares, get_document_versions)
from logger import security_log, access_log

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = Config.MAX_CONTENT_LENGTH
app.secret_key = Config.SECRET_KEY


#security headers
@app.after_request
def set_security_headers(response):
    response.headers['Content-Security-Policy'] = ("default-src 'self'; " "script-src 'self' 'unsafe-inline'; " "style-src 'self' 'unsafe-inline'; " "img-src 'self' data:; " "font-src 'self' data:; " "connect-src 'self'; " "frame-ancestors 'none'")
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response


#force https
@app.before_request
def require_https():
    if not Config.DEBUG and not request.is_secure:
        url = request.url.replace("http://", "https://", 1)
        return redirect(url, code=301)


#middleware for session
@app.before_request
def load_user():
    token = request.cookies.get('session_token')
    session_data = session_manager.validate_session(token) if token else None
    if session_data:
        g.user_id = session_data['user_id']
        g.user = get_user_by_id(g.user_id)
    else:
        g.user_id = None
        g.user = None


@app.after_request
def log_access(response):
    #this skips static files
    if not request.path.startswith('/static'):
        access_log.log_request(request.method, request.path, response.status_code, g.get('user_id'), request.remote_addr)
    return response


#auth decorators
def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not g.user_id:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def require_role(role):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not g.user:
                return redirect(url_for('login'))
            if g.user.get('role') != role:
                security_log.log_event('ACCESS_DENIED', user_id=g.user_id, details={'resource': request.path, 'reason': 'Insufficient role'}, severity='WARNING', ip_address=request.remote_addr)
                abort(403)
            return f(*args, **kwargs)
        return decorated
    return decorator


def guest_or_above(f):
    """Allow guest (unauthenticated) and above."""
    return f


#error handling
@app.errorhandler(403)
def forbidden(e):
    return render_template('error.html', code=403, message="You don't have permission to access this resource."), 403

@app.errorhandler(404)
def not_found(e):
    return render_template('error.html', code=404, message="The page you're looking for doesn't exist."), 404

@app.errorhandler(413)
def too_large(e):
    return render_template('error.html', code=413, message="File is too large. Maximum size is 16MB."), 413

@app.errorhandler(500)
def server_error(e):
    security_log.log_event('SERVER_ERROR', details={'path': request.path}, severity='ERROR', ip_address=request.remote_addr)
    return render_template('error.html', code=500, message="An internal error occurred."), 500


#public routes
@app.route('/')
def index():
    if g.user:
        return redirect(url_for('dashboard'))
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if g.user:
        return redirect(url_for('dashboard'))
    error = None

    if request.method == 'POST':
        username = sanitize_input(request.form.get('username', ''))
        email = sanitize_input(request.form.get('email', ''))
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')

        if password != confirm:
            error = "Passwords do not match."
        else:
            result = register_user(username, email, password)

            if 'error' in result:
                error = result['error']
            else:
                flash('Account created. Please log in.', 'success')
                return redirect(url_for('login'))
            
    return render_template('register.html', error=error)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if g.user:
        return redirect(url_for('dashboard'))
    error = None
    if request.method == 'POST':
        username = sanitize_input(request.form.get('username', ''))
        password = request.form.get('password', '')
        result = authenticate_user(username, password, ip_address=request.remote_addr, user_agent=request.headers.get('User-Agent'))
        if 'error' in result:
            error = result['error']
        else:
            user = result['user']
            token = session_manager.create_session(
                user['id'],
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent')
            )
            response = make_response(redirect(url_for('dashboard')))
            response.set_cookie(
                'session_token', token,
                httponly=True,
                secure=not Config.DEBUG,
                samesite='Strict',
                max_age=Config.SESSION_TIMEOUT
            )
            return response
    return render_template('login.html', error=error)


@app.route('/logout')
def logout():
    token = request.cookies.get('session_token')
    if token:
        session_manager.destroy_session(token, user_id=g.user_id)
    response = make_response(redirect(url_for('index')))
    response.delete_cookie('session_token')
    return response


#authenticared routes

@app.route('/dashboard')
@require_auth

def dashboard():
    docs = get_user_documents(g.user_id)
    #sort by upload time going down
    docs.sort(key=lambda d: d.get('uploaded_at', 0), reverse=True)
    return render_template('dashboard.html', user=g.user, documents=docs)


@app.route('/upload', methods=['GET', 'POST'])
@require_auth

def upload():
    if g.user.get('role') == 'guest':
        abort(403)
    error = None
    if request.method == 'POST':
        file = request.files.get('file')
        description = sanitize_input(request.form.get('description', ''))
        if not file or not file.filename:
            error = "No file selected."
        else:
            result = upload_document(g.user_id, g.user['username'], file, file.filename, description)
            if 'error' in result:
                error = result['error']
            else:
                flash('Document uploaded successfully.', 'success')
                return redirect(url_for('dashboard'))
    return render_template('upload.html', user=g.user, error=error, allowed=', '.join(Config.ALLOWED_EXTENSIONS))

@app.route('/document/<doc_id>')
@require_auth

def view_document(doc_id):
    doc = get_document(doc_id)
    if not doc:
        abort(404)
    from documents import can_access
    if not can_access(doc_id, g.user_id, 'viewer'):
        abort(403)
    shares = []
    if doc['owner_id'] == g.user_id or g.user.get('role') == 'admin':
        shares = get_document_shares(doc_id, g.user_id if doc['owner_id'] == g.user_id else doc['owner_id'])
        if isinstance(shares, dict) and 'error' in shares:
            #get shares differently (bc admin viewing)
            from documents import _load_shares
            from auth import get_user_by_id
            raw = _load_shares().get(doc_id, {})
            shares = [{'user_id': uid, 'username': (get_user_by_id(uid) or {}).get('username','?'), 'role': r}
                      for uid, r in raw.items()]
    versions = get_document_versions(doc_id, g.user_id)
    if isinstance(versions, dict):
        versions = []
    from documents import _load_shares
    user_role_on_doc = 'owner' if doc['owner_id'] == g.user_id else \
                       _load_shares().get(doc_id, {}).get(g.user_id, 'viewer')
    if g.user.get('role') == 'admin':
        user_role_on_doc = 'admin'
    return render_template('document.html', user=g.user, doc=doc,
                           shares=shares, versions=versions,
                           user_role=user_role_on_doc)


@app.route('/document/<doc_id>/download')
@require_auth

def download(doc_id):
    result = download_document(doc_id, g.user_id, g.user['username'])
    if 'error' in result:
        abort(403 if result['error'] == 'Access denied.' else 404)

    mime = mimetypes.guess_type(result['filename'])[0] or 'application/octet-stream'
    return send_file(
        io.BytesIO(result['data']),
        mimetype=mime,
        as_attachment=True,
        download_name=result['filename']
    )



@app.route('/document/<doc_id>/update', methods=['POST'])
@require_auth

def update_doc(doc_id):
    if g.user.get('role') == 'guest':
        abort(403)
    file = request.files.get('file')
    if not file or not file.filename:
        flash('No file selected.', 'error')
        return redirect(url_for('view_document', doc_id=doc_id))
    result = update_document(doc_id, g.user_id, g.user['username'], file, file.filename)
    if 'error' in result:
        flash(result['error'], 'error')
    else:
        flash(f"Document updated to version {result['version']}.", 'success')
    return redirect(url_for('view_document', doc_id=doc_id))


@app.route('/document/<doc_id>/delete', methods=['POST'])
@require_auth

def delete_doc(doc_id):
    result = delete_document(doc_id, g.user_id, g.user.get('role', 'user'))
    if 'error' in result:
        flash(result['error'], 'error')
    else:
        flash('Document deleted.', 'success')
    return redirect(url_for('dashboard'))


@app.route('/document/<doc_id>/share', methods=['POST'])
@require_auth

def share_doc(doc_id):
    target = sanitize_input(request.form.get('username', ''))
    role = request.form.get('role', 'viewer')
    result = share_document(doc_id, g.user_id, target, role)
    if 'error' in result:
        flash(result['error'], 'error')
    else:
        flash(f'Document shared with {html.escape(target)} as {role}.', 'success')
    return redirect(url_for('view_document', doc_id=doc_id))


@app.route('/document/<doc_id>/unshare', methods=['POST'])
@require_auth
def unshare_doc(doc_id):
    target_uid = request.form.get('user_id', '')
    result = unshare_document(doc_id, g.user_id, target_uid)
    if 'error' in result:
        flash(result['error'], 'error')
    else:
        flash('Access revoked.', 'success')
    return redirect(url_for('view_document', doc_id=doc_id))


@app.route('/account', methods=['GET', 'POST'])
@require_auth
def account():
    error = None
    success = None
    if request.method == 'POST':
        old_pw = request.form.get('old_password', '')
        new_pw = request.form.get('new_password', '')
        confirm = request.form.get('confirm_password', '')
        if new_pw != confirm:
            error = "New passwords do not match."
        else:
            result = change_password(g.user_id, old_pw, new_pw,
                                     ip_address=request.remote_addr)
            if 'error' in result:
                error = result['error']
            else:
                success = "Password changed successfully."

                #invalidates all sessions
                session_manager.destroy_all_user_sessions(g.user_id)
                response = make_response(redirect(url_for('login')))
                response.delete_cookie('session_token')
                flash('Password changed. Please log in again.', 'success')
                return response
    return render_template('account.html', user=g.user, error=error, success=success)


#admin routes

@app.route('/admin')
@require_auth
@require_role('admin')
def admin_dashboard():
    users = get_all_users()
    docs = get_all_documents()
    return render_template('admin.html', user=g.user, users=users, documents=docs)


@app.route('/admin/user/<user_id>/promote', methods=['POST'])
@require_auth
@require_role('admin')
def promote_user(user_id):
    from storage import enc_storage
    from config import Config
    users_data = enc_storage.load_encrypted(Config.USERS_FILE)
    for username, u in users_data.items():
        if u['id'] == user_id and u['role'] != 'admin':
            u['role'] = 'user' if u['role'] == 'guest' else 'admin'
            users_data[username] = u
            enc_storage.save_encrypted(Config.USERS_FILE, users_data)
            security_log.log_event('USER_ROLE_CHANGED', user_id=g.user_id, details={'target_user': user_id, 'new_role': u['role']})
            flash(f"User promoted to {u['role']}.", 'success')
            break
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/user/<user_id>/delete', methods=['POST'])
@require_auth
@require_role('admin')
def admin_delete_user(user_id):
    if user_id == g.user_id:
        flash("Cannot delete your own account.", 'error')
        return redirect(url_for('admin_dashboard'))
    from storage import enc_storage
    from config import Config
    users_data = enc_storage.load_encrypted(Config.USERS_FILE)
    to_remove = None
    for username, u in users_data.items():
        if u['id'] == user_id:
            to_remove = username
            break

    if to_remove:
        del users_data[to_remove]
        enc_storage.save_encrypted(Config.USERS_FILE, users_data)
        security_log.log_event('USER_DELETED', user_id=g.user_id, details={'target_user': user_id})
        flash("User deleted.", 'success')
    return redirect(url_for('admin_dashboard'))


#api endpoints

@app.route('/api/documents')
@require_auth
def api_documents():
    docs = get_user_documents(g.user_id)
    return jsonify({'documents': docs})


if __name__ == '__main__':
    #creates default admin account if no users exist
    from auth import get_user_by_username, register_user as _reg
    from storage import enc_storage
    if not enc_storage.load_encrypted(Config.USERS_FILE):
        _reg('admin', 'admin@securedocs.local', 'Admin@SecureDocs1!', role='admin')
        print("[*] Default admin created: admin / Admin@SecureDocs1!")
        print("[!] Change the admin password immediately after first login")

    app.run(
        debug=Config.DEBUG,
        host='127.0.0.1',
        port=5000
    )
