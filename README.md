(SecureDocs) Secure Document Sharing System Project
CS 419 Secure Web Application Project, Spring 2026

Flask-based encrypted document sharing system with role-based access control, full audit trails, and comprehensive security controls.


Setup:

1. Clone/enter the project directory

2. Install Python dependencies if needed with: pip install -r requirements.txt

3. Run app with: python app.py, you can open the link http://localhost:5000 in your browser to view the page

The default admin account, which is created automatically on first run, have these credentials:
Username: admin
Password: Admin@SecureDocs1!
You can change this after the first login via Account Settings.

Project Structure

secure-app/
├── app.py              #main Flask application, routes, and security headers
├── auth.py             #registration, login, password hashing, rate limiting
├── sessions.py         #session creation, validation, destruction
├── documents.py        #upload, download, share, version management
├── storage.py          #fernet encrypted storage and plain JSON store
├── logger.py           #security event logger and access logger
├── config.py           #configuration like paths, timeouts, limits
├── requirements.txt    #python dependencies
│
├── data/               #runtime data (gitignored)
│   ├── users.json      #encrypted user accounts
│   ├── sessions.json   #encrypted active sessions
│   ├── documents.json  #document metadata
│   ├── shares.json     #share grants
│   ├── versions.json   #version history
│   ├── secret.key      #fernet master key 
│   └── uploads/        #encrypted document files
│
├── logs/               #auto created log files 
│   ├── security.log    #security events
│   └── access.log      #HTTP access log
│
├── static/             
├── templates/          #HTML templates
│   ├── base.html
│   ├── index.html
│   ├── login.html
│   ├── register.html
│   ├── dashboard.html
│   ├── upload.html
│   ├── document.html
│   ├── admin.html
│   ├── account.html
│   └── error.html
│
├── docs/
│   ├── security_design.docx   #security design doc
│   └── pentest_report.docx    #penetration testing doc
│
├── tests/
│   └── test_security.py       #57 security tests
│
└── presentation/
    └── SecureDocs_Presentation.pptx


To run tests, use: python tests/test_security.py

Expected output: `Ran 57 tests ... OK`




Production Deployment Notes

1. Set environment variables instead of using defaults:
   export SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
   export FERNET_KEY=$(cat data/secret.key | base64)
   export FLASK_ENV=production



2. Restrict file permissions:
   chmod 600 data/secret.key
   chmod 700 data/ logs/

3. Do not run as root, use a dedicated system user.

4. Set up log rotation for logs/security.log and logs/access.log

Dependencies include:

flask>=3.0.0
bcrypt>=4.1.0
cryptography>=42.0.0
PyJWT>=2.8.0
Werkzeug>=3.0.0
python-dotenv>=1.0.0

you can install with: pip install -r requirements.txt



