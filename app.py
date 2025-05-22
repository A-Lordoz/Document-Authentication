from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory, make_response
from flask_mysqldb import MySQL
from flask_session import Session
import bcrypt
import os
import re
from dotenv import load_dotenv
from authlib.integrations.flask_client import OAuth
from functools import wraps
from werkzeug.utils import secure_filename
from utils.encryption import encrypt_file
from utils.signature import generate_keys, sign_data, verify_signature
import hashlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import tempfile
import mimetypes
from docx import Document as DocxDocument
import threading
import time
import pyotp
import qrcode
import io
import base64


# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'fallback-secret-key')

# Database configuration
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = os.getenv('DB_PASSWORD', '')
app.config['MYSQL_DB'] = 'dataproject'
app.config['SESSION_TYPE'] = 'filesystem'

# Initialize extensions
mysql = MySQL(app)
Session(app)

# Initialize OAuth
oauth = OAuth(app)

# Register GitHub OAuth
github = oauth.register(
    name='github',
    client_id=os.getenv('GITHUB_CLIENT_ID'),
    client_secret=os.getenv('GITHUB_CLIENT_SECRET'),
    access_token_url='https://github.com/login/oauth/access_token',
    authorize_url='https://github.com/login/oauth/authorize',
    api_base_url='https://api.github.com/',
    client_kwargs={'scope': 'user:email'},
)

# Register Google OAuth with server_metadata_url
google = oauth.register(
    name='google',
    client_id=os.getenv('GOOGLE_CLIENT_ID'),
    client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
    access_token_url='https://oauth2.googleapis.com/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    api_base_url='https://www.googleapis.com/oauth2/v3/',
    client_kwargs={'scope': 'openid email profile'},
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration'
)
# Register Facebook OAuth
facebook = oauth.register(
    name='facebook',
    client_id=os.getenv('FACEBOOK_CLIENT_ID'),
    client_secret=os.getenv('FACEBOOK_CLIENT_SECRET'),
    access_token_url='https://graph.facebook.com/v12.0/oauth/access_token',
    authorize_url='https://www.facebook.com/v12.0/dialog/oauth',
    api_base_url='https://graph.facebook.com/v12.0/',
    client_kwargs={'scope': 'email'},
)

# ==================== Helper Functions ====================

def is_password_strong(password):
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    if not re.search(r"[!@#$%^&*()_+]", password):
        return False
    return True

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('You must be logged in to access this page.', 'warning')
            return redirect(url_for('login'))
        if not session.get('2fa_authenticated'):
            return redirect(url_for('two_factor'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin'):
            flash('Admin access required.', 'danger')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

def superadmin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_superadmin'):
            flash('Super admin access required.', 'danger')
            return redirect(url_for('admin_panel'))
        return f(*args, **kwargs)
    return decorated_function

def get_totp_uri(username, secret):
    return pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="DocumentVault")

def generate_qr_code_image(uri):
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    qr_b64 = base64.b64encode(buf.getvalue()).decode('utf-8')
    return qr_b64

# ==================== Routes ====================

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/delete_document/<int:doc_id>', methods=['POST'])
@login_required
def delete_document(doc_id):
    cursor = mysql.connection.cursor()
    # Fetch file paths and owner
    cursor.execute('SELECT user_id, filename, encrypted_path, signature_path, public_key_path FROM documents WHERE id = %s', (doc_id,))
    doc = cursor.fetchone()
    if not doc:
        flash('Document not found.', 'danger')
        return redirect(url_for('home'))
    if doc[0] != session['user_id'] and not session.get('is_superadmin'):
        flash('You do not have permission to delete this document.', 'danger')
        return redirect(url_for('home'))

    # Build absolute paths
    username = session['username']
    enc_abs = os.path.join(app.config['UPLOAD_FOLDER'], doc[2])
    sig_abs = os.path.join(app.config['UPLOAD_FOLDER'], doc[3])
    pubkey_abs = os.path.join(app.config['UPLOAD_FOLDER'], doc[4])
    # Optionally, also delete the .key file if you store it
    key_abs = enc_abs.rsplit('.', 1)[0] + '.key'

    # Delete files if they exist
    for path in [enc_abs, sig_abs, pubkey_abs, key_abs]:
        try:
            if os.path.isfile(path):
                os.remove(path)
        except Exception:
            pass

    # Optionally, remove the document folder if empty
    doc_folder = os.path.dirname(enc_abs)
    try:
        if os.path.isdir(doc_folder) and not os.listdir(doc_folder):
            os.rmdir(doc_folder)
    except Exception:
        pass

    # Delete DB record
    cursor.execute('DELETE FROM documents WHERE id = %s', (doc_id,))
    mysql.connection.commit()
    cursor.close()
    log_action(session['user_id'], f"Deleted document: {doc[1]}")
    flash('Document and its files deleted successfully.', 'success')
    return redirect(url_for('home'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('signup'))

        if not is_password_strong(password):
            flash('Password must contain: 8+ chars, 1 uppercase, 1 lowercase, 1 number, 1 special char', 'danger')
            return redirect(url_for('signup'))

        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        cursor = mysql.connection.cursor()
        try:
            cursor.execute('SELECT * FROM users WHERE username = %s OR email = %s', (username, email))
            existing_user = cursor.fetchone()
            if existing_user:
                flash('Username or email already exists', 'danger')
                return redirect(url_for('signup'))

            cursor.execute(
                'INSERT INTO users (username, email, password_hash, auth_method) VALUES (%s, %s, %s, %s)',
                (username, email, hashed_pw, 'manual')
            )
            mysql.connection.commit()
            user_id = cursor.lastrowid
            session['pending_2fa_user_id'] = user_id  # Store for 2FA setup
            flash('Account created! Set up 2FA to continue.', 'success')
            return redirect(url_for('two_factor_setup'))
        except Exception as e:
            mysql.connection.rollback()
            flash('An error occurred while creating your account', 'danger')
        finally:
            cursor.close()

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username_or_email = request.form['username_or_email']
        password = request.form['password']

        cursor = mysql.connection.cursor()
        cursor.execute(
            'SELECT id, username, password_hash, is_admin, is_superadmin FROM users WHERE username = %s OR email = %s',
            (username_or_email, username_or_email)
        )
        user = cursor.fetchone()

        if user and bcrypt.checkpw(password.encode('utf-8'), user[2].encode('utf-8')):
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['is_admin'] = user[3]
            session['is_superadmin'] = user[4]
            session['2fa_authenticated'] = False
            # Log login
            cursor.execute(
                "INSERT INTO login_logs (user_id, ip_address) VALUES (%s, %s)",
                (user[0], request.remote_addr)
            )
            mysql.connection.commit()
            cursor.close()
            return redirect(url_for('two_factor'))
        else:
            cursor.close()
            flash('Invalid credentials', 'danger')
    return render_template('login.html')

@app.route('/login/github')
def github_login():
    callback_url = url_for('github_callback', _external=True)
    return github.authorize_redirect(callback_url)

@app.route('/login/github/callback')
def github_callback():
    cursor = None
    try:
        token = github.authorize_access_token()
        if not token:
            flash('GitHub authorization failed', 'danger')
            return redirect(url_for('login'))

        resp = github.get('user')
        if resp.status_code != 200:
            flash('Failed to fetch user data from GitHub', 'danger')
            return redirect(url_for('login'))

        user_info = resp.json()
        github_id = str(user_info['id'])
        email = user_info.get('email') or f"{user_info['login']}@users.noreply.github.com"

        cursor = mysql.connection.cursor()
        cursor.execute('SELECT * FROM users WHERE github_id = %s', (github_id,))
        user = cursor.fetchone()

        if not user:
            cursor.execute(
                'INSERT INTO users (username, email, github_id, auth_method) VALUES (%s, %s, %s, %s)',
                (user_info['login'], email, github_id, 'github')
            )
            mysql.connection.commit()
            user_id = cursor.lastrowid
            is_admin = 0
            is_superadmin = 0
        else:
            user_id = user[0]
            is_admin = user[14] if len(user) > 14 else 0
            is_superadmin = user[15] if len(user) > 15 else 0

        session['user_id'] = user_id
        session['username'] = user_info['login']
        session['is_admin'] = is_admin
        session['is_superadmin'] = is_superadmin
        session['2fa_authenticated'] = False
        # Log login
        cursor.execute(
            "INSERT INTO login_logs (user_id, ip_address) VALUES (%s, %s)",
            (user_id, request.remote_addr)
        )
        mysql.connection.commit()

        flash('Login successful via GitHub!', 'success')
        return redirect(url_for('admin_panel') if is_superadmin else url_for('home'))

    except Exception as e:
        flash(f'GitHub login error: {str(e)}', 'danger')
        return redirect(url_for('login'))
    finally:
        if cursor:
            cursor.close()

@app.route('/login/google')
def google_login():
    callback_url = url_for('google_callback', _external=True)
    return google.authorize_redirect(callback_url)

@app.route('/login/google/callback')
def google_callback():
    cursor = None
    try:
        token = google.authorize_access_token()
        if not token:
            flash('Google authorization failed', 'danger')
            return redirect(url_for('login'))

        resp = google.get('userinfo')
        if resp.status_code != 200:
            flash(f'Failed to fetch user data from Google: {resp.text}', 'danger')
            return redirect(url_for('login'))

        user_info = resp.json()
        google_id = str(user_info.get('id'))
        if not google_id:
            flash('Google ID not found in user data', 'danger')
            return redirect(url_for('login'))

        email = user_info.get('email')
        username = user_info.get('name') or email.split('@')[0]

        cursor = mysql.connection.cursor()
        cursor.execute('SELECT * FROM users WHERE google_id = %s', (google_id,))
        user = cursor.fetchone()

        if not user:
            cursor.execute(
                'INSERT INTO users (username, email, google_id, auth_method) VALUES (%s, %s, %s, %s)',
                (username, email, google_id, 'google')
            )
            mysql.connection.commit()
            user_id = cursor.lastrowid
            is_admin = 0
            is_superadmin = 0
        else:
            user_id = user[0]
            is_admin = user[14] if len(user) > 14 else 0
            is_superadmin = user[15] if len(user) > 15 else 0

        session['user_id'] = user_id
        session['username'] = username
        session['is_admin'] = is_admin
        session['is_superadmin'] = is_superadmin
        session['2fa_authenticated'] = False
        # Log login
        cursor.execute(
            "INSERT INTO login_logs (user_id, ip_address) VALUES (%s, %s)",
            (user_id, request.remote_addr)
        )
        mysql.connection.commit()

        flash('Login successful via Google!', 'success')
        return redirect(url_for('admin_panel') if is_superadmin else url_for('home'))

    except Exception as e:
        flash(f'Google login error: {str(e)}', 'danger')
        return redirect(url_for('login'))
    finally:
        if cursor:
            cursor.close()

@app.route('/login/facebook')
def facebook_login():
    callback_url = url_for('facebook_callback', _external=True)
    return facebook.authorize_redirect(callback_url)

@app.route('/login/facebook/callback')
def facebook_callback():
    cursor = None
    try:
        token = facebook.authorize_access_token()
        if not token:
            flash('Facebook authorization failed', 'danger')
            return redirect(url_for('login'))

        resp = facebook.get('me?fields=id,name,email')
        if resp.status_code != 200:
            flash('Failed to fetch user data from Facebook', 'danger')
            return redirect(url_for('login'))

        user_info = resp.json()
        facebook_id = str(user_info.get('id'))
        email = user_info.get('email') or f"{facebook_id}@facebook.local"
        username = user_info.get('name')

        cursor = mysql.connection.cursor()
        cursor.execute('SELECT * FROM users WHERE facebook_id = %s', (facebook_id,))
        user = cursor.fetchone()

        if not user:
            cursor.execute(
                'INSERT INTO users (username, email, facebook_id, auth_method) VALUES (%s, %s, %s, %s)',
                (username, email, facebook_id, 'facebook')
            )
            mysql.connection.commit()
            user_id = cursor.lastrowid
            is_admin = 0
            is_superadmin = 0
        else:
            user_id = user[0]
            is_admin = user[14] if len(user) > 14 else 0
            is_superadmin = user[15] if len(user) > 15 else 0

        session['user_id'] = user_id
        session['username'] = username
        session['is_admin'] = is_admin
        session['is_superadmin'] = is_superadmin
        session['2fa_authenticated'] = False
        # Log login
        cursor.execute(
            "INSERT INTO login_logs (user_id, ip_address) VALUES (%s, %s)",
            (user_id, request.remote_addr)
        )
        mysql.connection.commit()

        flash('Login successful via Facebook!', 'success')
        return redirect(url_for('admin_panel') if is_superadmin else url_for('home'))

    except Exception as e:
        flash(f'Facebook login error: {str(e)}', 'danger')
        return redirect(url_for('login'))
    finally:
        if cursor:
            cursor.close()


@app.route('/home', methods=['GET', 'POST'])
@login_required
def home():
    decrypted_results = {}
    if request.method == 'POST':
        enc_path = request.form['enc_path']
        aes_key_file = request.files['aes_key']

        if enc_path and aes_key_file:
            abs_enc_path = os.path.join(app.config['UPLOAD_FOLDER'], enc_path)
            if os.path.isfile(abs_enc_path):
                try:
                    aes_key = aes_key_file.read()
                    from utils.encryption import decrypt_file as aes_decrypt_file
                    with open(abs_enc_path, 'rb') as f:
                        encrypted_bytes = f.read()
                    decrypted_data = aes_decrypt_file(encrypted_bytes, aes_key)

                    # Detect file type by extension
                    ext = os.path.splitext(enc_path)[0].split('.')[-1].lower()
                    if ext == 'pdf':
                        # Save decrypted PDF to a temp file in static/
                        decrypted_dir = os.path.join('static', 'decrypted')
                        os.makedirs(decrypted_dir, exist_ok=True)
                        temp_pdf = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf', dir=decrypted_dir)
                        temp_pdf.write(decrypted_data)
                        temp_pdf.close()
                        decrypted_results[enc_path] = {
                            'type': 'pdf',
                            'path': 'decrypted/' + os.path.basename(temp_pdf.name)
                        }
                    elif ext == 'docx':
                        # Save decrypted DOCX to a temp file, extract text
                        temp_docx = tempfile.NamedTemporaryFile(delete=False, suffix='.docx')
                        temp_docx.write(decrypted_data)
                        temp_docx.close()
                        doc = DocxDocument(temp_docx.name)
                        text = '\n'.join([para.text for para in doc.paragraphs])
                        decrypted_results[enc_path] = {
                            'type': 'docx',
                            'text': text
                        }
                        os.unlink(temp_docx.name)
                    else:
                        # Assume text file
                        try:
                            plaintext = decrypted_data.decode('utf-8')
                        except Exception:
                            plaintext = decrypted_data.hex()
                        decrypted_results[enc_path] = {
                            'type': 'text',
                            'text': plaintext
                        }
                except Exception as e:
                    decrypted_results[enc_path] = {
                        'type': 'error',
                        'text': f'Decryption failed: {str(e)}'
                    }
            else:
                decrypted_results[enc_path] = {
                    'type': 'error',
                    'text': 'Encrypted file not found.'
                }

    cursor = mysql.connection.cursor()
    cursor.execute('SELECT username, nickname, photo FROM users WHERE id = %s', (session['user_id'],))
    user = cursor.fetchone()
    username = user[0]
    nickname = user[1] if user[1] else username
    user_photo = user[2] if user[2] else None

    
    cursor.execute(
        "SELECT filename, encrypted_path, signature_path, uploaded_at, id FROM documents WHERE user_id = %s",
        (session['user_id'],)
    )
    documents = cursor.fetchall()
    cursor.close()
    return render_template(
        'home.html',
        username=username,
        nickname=nickname,
        user_photo=user_photo,
        documents=documents,
        decrypted_results=decrypted_results
    )

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out successfully', 'success')
    return redirect(url_for('login'))

UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        file = request.files.get('file')
        if not file or file.filename == '':
            flash('No file selected', 'danger')
            return redirect(request.url)

        file_data = file.read()
        key = os.urandom(16)
        encrypted_data = encrypt_file(file_data, key)

        private_key, public_key = generate_keys()
        signature = sign_data(private_key, file_data)

        filename = secure_filename(file.filename)
        file_type = filename.split('.')[-1]
        sha256_hash = hashlib.sha256(file_data).hexdigest()
        username = session['username']

        # Create user and document-specific folders
        user_folder = os.path.join(app.config['UPLOAD_FOLDER'], username)
        doc_folder = os.path.join(user_folder, filename)
        os.makedirs(doc_folder, exist_ok=True)

        enc_filename = filename + '.enc'
        sig_filename = filename + '.sig'
        key_filename = filename + '.key'
        pubkey_filename = filename + '.pub'

        enc_path = os.path.join(doc_folder, enc_filename)
        sig_path = os.path.join(doc_folder, sig_filename)
        key_path = os.path.join(doc_folder, key_filename)
        pubkey_path = os.path.join(doc_folder, pubkey_filename)

        with open(enc_path, 'wb') as f:
            f.write(encrypted_data)
        with open(sig_path, 'wb') as f:
            f.write(signature)
        with open(key_path, 'wb') as f:
            f.write(key)
        with open(pubkey_path, 'wb') as f:
            f.write(
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )

        # Save relative paths to DB
        cursor = mysql.connection.cursor()
        cursor.execute(
            "INSERT INTO documents (user_id, filename, encrypted_path, file_type, sha256_hash, signature_path, public_key_path) VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (
                session['user_id'],
                filename,
                '/'.join([username, filename, enc_filename]),
                file_type,
                sha256_hash,
                '/'.join([username, filename, sig_filename]),
                '/'.join([username, filename, pubkey_filename])
            )
        )
        mysql.connection.commit()

        cursor.execute(
            "INSERT INTO system_logs (user_id, action) VALUES (%s, %s)",
            (session['user_id'], 'Uploaded a document')
        )
        mysql.connection.commit()

        cursor.close()

        flash('File uploaded, encrypted, and signed successfully!', 'success')
        return redirect(url_for('upload'))

    cursor = mysql.connection.cursor()
    cursor.execute('SELECT username, nickname, photo FROM users WHERE id = %s', (session['user_id'],))
    user = cursor.fetchone()
    cursor.close()
    nickname = user[1] if user[1] else user[0]
    user_photo = user[2] if user[2] else None
    return render_template('upload.html', nickname=nickname, user_photo=user_photo)

@app.route('/my_documents')
@login_required
def my_documents():
    cursor = mysql.connection.cursor()
    cursor.execute(
        "SELECT filename, encrypted_path, signature_path, uploaded_at FROM documents WHERE user_id = %s",
        (session['user_id'],)
    )
    docs = cursor.fetchall()
    cursor.execute('SELECT username, nickname, photo FROM users WHERE id = %s', (session['user_id'],))
    user = cursor.fetchone()
    cursor.close()
    nickname = user[1] if user[1] else user[0]
    user_photo = user[2] if user[2] else None
    return render_template('my_documents.html', documents=docs, nickname=nickname, user_photo=user_photo)

@app.route('/download/<path:filepath>')
@login_required
def download_file(filepath):
    abs_path = os.path.join(app.config['UPLOAD_FOLDER'], filepath)
    if not os.path.isfile(abs_path):
        flash('File not found or access denied.', 'danger')
        return redirect(url_for('my_documents'))
    return send_from_directory(app.config['UPLOAD_FOLDER'], filepath, as_attachment=True)

@app.route('/verify_signature', methods=['GET', 'POST'])
@login_required
def verify_signature_route():
    result = None
    documents = []
    cursor = mysql.connection.cursor()
    cursor.execute(
        "SELECT id, filename, signature_path, public_key_path FROM documents WHERE user_id = %s",
        (session['user_id'],)
    )
    documents = cursor.fetchall()
    cursor.close()

    if request.method == 'POST':
        doc_id = request.form.get('document')
        file = request.files.get('file')
        sig_file = request.files.get('signature')
        if not doc_id or not file or not sig_file:
            flash('Please select a document and upload the file and signature.', 'danger')
            return redirect(request.url)

        # Get the selected document's public key path
        selected_doc = next((doc for doc in documents if str(doc[0]) == doc_id), None)
        if not selected_doc:
            flash('Document not found.', 'danger')
            return redirect(request.url)

        pubkey_path = os.path.join(app.config['UPLOAD_FOLDER'], selected_doc[3])
        with open(pubkey_path, 'rb') as f:
            public_key_data = f.read()

        file_data = file.read()
        signature = sig_file.read()

        from cryptography.hazmat.primitives import serialization
        public_key = serialization.load_pem_public_key(public_key_data)

        try:
            valid = verify_signature(public_key, file_data, signature)
            result = "Signature is VALID." if valid else "Signature is INVALID."
        except Exception as e:
            result = f"Verification error: {str(e)}"

    cursor = mysql.connection.cursor()
    cursor.execute('SELECT username, nickname, photo FROM users WHERE id = %s', (session['user_id'],))
    user = cursor.fetchone()
    cursor.close()
    nickname = user[1] if user[1] else user[0]
    user_photo = user[2] if user[2] else None
    return render_template('verify_signature.html', result=result, documents=documents, nickname=nickname, user_photo=user_photo)

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    cursor = mysql.connection.cursor()
    cursor.execute('SELECT username, email, nickname, photo, password_hash FROM users WHERE id = %s', (session['user_id'],))
    user = cursor.fetchone()
    user_dict = {
        'username': user[0],
        'email': user[1],
        'nickname': user[2],
        'photo': user[3]
    }
    user_photo = user[3] if user[3] else None
    nickname = user[2] if user[2] else user[0]

    if request.method == 'POST':
        # Handle password change
        if request.form.get('change_password'):
            old_password = request.form.get('old_password')
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')

            if not bcrypt.checkpw(old_password.encode('utf-8'), user[4].encode('utf-8')):
                flash('Old password is incorrect.', 'danger')
            elif new_password != confirm_password:
                flash('New passwords do not match.', 'danger')
            elif not is_password_strong(new_password):
                flash('Password must contain: 8+ chars, 1 uppercase, 1 lowercase, 1 number, 1 special char', 'danger')
            else:
                hashed_pw = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
                cursor.execute('UPDATE users SET password_hash = %s WHERE id = %s', (hashed_pw, session['user_id']))
                mysql.connection.commit()
                flash('Password changed successfully!', 'success')
        else:
            # Handle nickname/photo update as before
            nickname = request.form.get('nickname')
            photo = request.files.get('photo')
            photo_filename = user[3]
            if photo and photo.filename:
                photo_filename = secure_filename(photo.filename)
                photo.save(os.path.join('static/profile_photos', photo_filename))
            cursor.execute('UPDATE users SET nickname = %s, photo = %s WHERE id = %s', (nickname, photo_filename, session['user_id']))
            mysql.connection.commit()
            flash('Profile updated!', 'success')
            user_dict['nickname'] = nickname
            user_dict['photo'] = photo_filename
            user_photo = photo_filename

    cursor.close()
    return render_template('profile.html', user=user_dict, user_photo=user_photo, nickname=nickname)

@app.route('/admin_panel')
@superadmin_required
def admin_panel():
    cursor = mysql.connection.cursor()
    cursor.execute('SELECT username, nickname, photo FROM users WHERE id = %s', (session['user_id'],))
    user = cursor.fetchone()
    cursor.close()
    nickname = user[1] if user[1] else user[0]
    user_photo = user[2] if user[2] else None
    return render_template('admin_panel.html', nickname=nickname, user_photo=user_photo)

def log_action(user_id, action):
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO system_logs (user_id, action) VALUES (%s, %s)",
        (user_id, action)
    )
    mysql.connection.commit()
    cursor.close()

@app.route('/admin/users', methods=['GET', 'POST'])
@superadmin_required
def admin_users():
    cursor = mysql.connection.cursor()
    if request.method == 'POST':
        # Add user logic (you can expand this)
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        if username and email and password:
            hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            cursor.execute('INSERT INTO users (username, email, password_hash, auth_method) VALUES (%s, %s, %s, %s)', (username, email, hashed_pw, 'manual'))
            mysql.connection.commit()
            flash('User added!', 'success')
    cursor.execute('SELECT id, username, email, nickname, is_admin FROM users')
    users = cursor.fetchall()
    cursor.close()
    nickname, user_photo = get_admin_sidebar_info()
    return render_template('admin_users.html', users=users, nickname=nickname, user_photo=user_photo)

@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@admin_required
def admin_delete_user(user_id):
    cursor = mysql.connection.cursor()
    cursor.execute('DELETE FROM users WHERE id = %s', (user_id,))
    mysql.connection.commit()
    cursor.close()
    flash('User deleted!', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/documents', methods=['GET', 'POST'])
@admin_required
def admin_documents():
    cursor = mysql.connection.cursor()
    cursor.execute('SELECT id, username FROM users')
    users = cursor.fetchall()
    selected_user = request.form.get('user_id') if request.method == 'POST' else None
    if selected_user:
        cursor.execute('SELECT d.id, d.filename, d.encrypted_path, d.uploaded_at FROM documents d JOIN users u ON d.user_id = u.id WHERE u.id = %s', (selected_user,))
    else:
        cursor.execute('SELECT d.id, d.filename, d.encrypted_path, d.uploaded_at, u.username FROM documents d JOIN users u ON d.user_id = u.id')
    documents = cursor.fetchall()
    cursor.close()
    nickname, user_photo = get_admin_sidebar_info()
    return render_template('admin_documents.html', users=users, documents=documents, selected_user=selected_user, nickname=nickname, user_photo=user_photo)

@app.route('/admin/documents/delete/<int:doc_id>', methods=['POST'])
@admin_required
def admin_delete_document(doc_id):
    cursor = mysql.connection.cursor()
    cursor.execute('DELETE FROM documents WHERE id = %s', (doc_id,))
    mysql.connection.commit()
    cursor.close()
    flash('Document deleted!', 'success')
    return redirect(url_for('admin_documents'))

@app.route('/admin/logs')
@admin_required
def admin_logs():
    cursor = mysql.connection.cursor()
    cursor.execute('SELECT id, username FROM users')
    users = cursor.fetchall()
    selected_user = request.args.get('user_id')
    if selected_user:
        cursor.execute('SELECT system_logs.*, users.username FROM system_logs JOIN users ON system_logs.user_id = users.id WHERE user_id = %s ORDER BY system_logs.timestamp DESC', (selected_user,))
    else:
        cursor.execute('SELECT system_logs.*, users.username FROM system_logs JOIN users ON system_logs.user_id = users.id ORDER BY system_logs.timestamp DESC')
    logs = cursor.fetchall()
    cursor.close()
    return render_template('admin_logs.html', logs=logs, users=users, selected_user=selected_user)

@app.route('/admin/roles', methods=['GET', 'POST'])
@superadmin_required
def admin_roles():
    cursor = mysql.connection.cursor()
    if request.method == 'POST':
        user_id = request.form.get('user_id')
        new_role = request.form.get('role')
        if user_id and new_role in ['admin', 'user']:
            is_admin = 1 if new_role == 'admin' else 0
            cursor.execute('UPDATE users SET is_admin = %s WHERE id = %s', (is_admin, user_id))
            mysql.connection.commit()
            flash('Role updated!', 'success')
            # Update session if current user
            if int(user_id) == session.get('user_id'):
                session['is_admin'] = is_admin
                if is_admin:
                    flash('You are now an admin! Admin features are available.', 'success')
                    return redirect(url_for('admin_panel'))
                else:
                    flash('You are now a regular user.', 'info')
                    return redirect(url_for('home'))
    cursor.execute('SELECT id, username, email, nickname, is_admin FROM users')
    users = cursor.fetchall()
    cursor.close()
    nickname, user_photo = get_admin_sidebar_info()
    return render_template('admin_roles.html', users=users, nickname=nickname, user_photo=user_photo)

def get_admin_sidebar_info():
    cursor = mysql.connection.cursor()
    cursor.execute('SELECT username, nickname, photo FROM users WHERE id = %s', (session['user_id'],))
    user = cursor.fetchone()
    cursor.close()
    nickname = user[1] if user[1] else user[0]
    user_photo = user[2] if user[2] else None
    return nickname, user_photo

@app.route('/decrypt_file', methods=['POST'])
@login_required
def decrypt_file_route():
    enc_path = request.form['enc_path']
    private_key_file = request.files['private_key']

    if not enc_path or not private_key_file:
        flash('Encrypted file path and private key are required.', 'danger')
        return redirect(url_for('home'))

    # Build absolute path to encrypted file
    abs_enc_path = os.path.join(app.config['UPLOAD_FOLDER'], enc_path)
    if not os.path.isfile(abs_enc_path):
        flash('Encrypted file not found.', 'danger')
        return redirect(url_for('home'))

    # Read encrypted data
    with open(abs_enc_path, 'rb') as f:
        encrypted_data = f.read()

    # Read private key
    try:
        private_key_data = private_key_file.read()
        private_key = serialization.load_pem_private_key(private_key_data, password=None)
    except Exception as e:
        flash(f'Invalid private key: {str(e)}', 'danger')
        return redirect(url_for('home'))

    # Decrypt the file (assuming AES key is stored somewhere, or the file is small and was encrypted with RSA directly)
    try:
        # If you encrypted with AES, you need to also upload the key or decrypt the AES key with RSA first.
        # Here, we assume the file was encrypted with AES and the key is stored as .key file in the same folder.
        key_path = abs_enc_path.rsplit('.', 1)[0] + '.key'
        if not os.path.isfile(key_path):
            flash('Encryption key file not found for this document.', 'danger')
            return redirect(url_for('home'))
        with open(key_path, 'rb') as f:
            aes_key = f.read()

        # Decrypt with AES
        from utils.encryption import decrypt_file as aes_decrypt_file
        decrypted_data = aes_decrypt_file(abs_enc_path, aes_key)
        # Try to decode as text, fallback to hex if not possible
        try:
            plaintext = decrypted_data.decode('utf-8')
        except Exception:
            plaintext = decrypted_data.hex()
    except Exception as e:
        flash(f'Decryption failed: {str(e)}', 'danger')
        return redirect(url_for('home'))

    # Show the decrypted text on a result page
    return render_template('decryption_result.html', plaintext=plaintext)

def cleanup_decrypted_folder():
    decrypted_dir = os.path.join('static', 'decrypted')
    while True:
        now = time.time()
        if os.path.exists(decrypted_dir):
            for filename in os.listdir(decrypted_dir):
                file_path = os.path.join(decrypted_dir, filename)
                if os.path.isfile(file_path):
                    # If file is older than 1 minute (60 seconds), delete it
                    if now - os.path.getmtime(file_path) > 60:
                        try:
                            os.remove(file_path)
                        except Exception:
                            pass
        time.sleep(60)  # Check every minute

# Start the cleanup thread
cleanup_thread = threading.Thread(target=cleanup_decrypted_folder, daemon=True)
cleanup_thread.start()

@app.after_request
def add_no_cache_headers(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response

# ==================== 2FA Routes ====================

@app.route('/2fa', methods=['GET', 'POST'])
def two_factor():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    cursor = mysql.connection.cursor()
    cursor.execute('SELECT username, totp_secret FROM users WHERE id = %s', (session['user_id'],))
    user = cursor.fetchone()
    cursor.close()
    username, totp_secret = user

    # If user has no secret, generate and store one
    if not totp_secret:
        totp_secret = pyotp.random_base32()
        cursor = mysql.connection.cursor()
        cursor.execute('UPDATE users SET totp_secret = %s WHERE id = %s', (totp_secret, session['user_id']))
        mysql.connection.commit()
        cursor.close()

    totp_uri = get_totp_uri(username, totp_secret)
    qr_b64 = generate_qr_code_image(totp_uri)

    if request.method == 'POST':
        code = request.form.get('code')
        totp = pyotp.TOTP(totp_secret)
        if totp.verify(code):
            session['2fa_authenticated'] = True
            # Redirect to home or admin_panel as appropriate
            if session.get('is_superadmin'):
                return redirect(url_for('admin_panel'))
            else:
                return redirect(url_for('home'))
        else:
            flash('Invalid 2FA code', 'danger')

    return render_template('2fa.html', qr_b64=qr_b64, totp_secret=totp_secret)

@app.route('/2fa_setup', methods=['GET', 'POST'])
def two_factor_setup():
    user_id = session.get('pending_2fa_user_id')
    if not user_id:
        return redirect(url_for('login'))

    cursor = mysql.connection.cursor()
    cursor.execute('SELECT username, totp_secret FROM users WHERE id = %s', (user_id,))
    user = cursor.fetchone()
    username, totp_secret = user

    # If user has no secret, generate and store one
    if not totp_secret:
        totp_secret = pyotp.random_base32()
        cursor.execute('UPDATE users SET totp_secret = %s WHERE id = %s', (totp_secret, user_id))
        mysql.connection.commit()

    totp_uri = get_totp_uri(username, totp_secret)
    qr_b64 = generate_qr_code_image(totp_uri)

    if request.method == 'POST':
        code = request.form.get('code')
        totp = pyotp.TOTP(totp_secret)
        if totp.verify(code):
            # 2FA setup complete, clear pending and redirect to login
            session.pop('pending_2fa_user_id', None)
            flash('2FA setup complete! Please log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Invalid 2FA code. Please try again.', 'danger')

    cursor.close()
    return render_template('2fa_setup.html', qr_b64=qr_b64, totp_secret=totp_secret)

# ==================== Run the Server ====================

if __name__ == '__main__':
    app.run(
        host='0.0.0.0',
        port=8000,
        ssl_context=('cert.pem', 'key.pem'),
        debug=True
    )