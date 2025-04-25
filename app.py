from flask import Flask, request, render_template, redirect, url_for, session, flash, current_app
from config import Config
from models import init_db, save_password, delete_password, update_password, get_user_passwords, log_audit
from security import init_limiter, validate_password_strength, hash_password, verify_password, generate_secure_password
from crypto import load_key, encrypt_password, decrypt_password
from functools import wraps
import logging
from logging.handlers import RotatingFileHandler
import os

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Initialize logging
    if not app.debug:
        if not os.path.exists('logs'):
            os.mkdir('logs')
        file_handler = RotatingFileHandler('logs/password_manager.log',
                                         maxBytes=10240, backupCount=10)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s '
            '[in %(pathname)s:%(lineno)d]'
        ))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
        app.logger.setLevel(logging.INFO)
        app.logger.info('Password Manager startup')

    # Initialize rate limiter
    limiter = init_limiter(app)

    # Initialize database within application context
    with app.app_context():
        init_db()
        # Load encryption key
        app.key = load_key()

    def login_required(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not session.get('user_id'):
                flash('Please log in to access this page.', 'warning')
                return redirect(url_for('login'))
            return f(*args, **kwargs)
        return decorated_function

    @app.route('/')
    def home():
        return redirect(url_for('login'))

    @app.route('/login', methods=['GET', 'POST'])
    @limiter.limit("5 per minute")
    def login():
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            
            with app.app_context():
                conn = current_app.config['db_connection']
                cur = conn.cursor()
                cur.execute("SELECT id, hashed_password FROM users WHERE username = %s", (username,))
                user = cur.fetchone()
                cur.close()

                if user and verify_password(user[1], password):
                    session['user_id'] = user[0]
                    log_audit(user[0], 'login', 'Successful login', request.remote_addr)
                    flash('Login successful!', 'success')
                    return redirect(url_for('dashboard'))
                
                log_audit(None, 'login_failed', f'Failed login attempt for username: {username}', request.remote_addr)
                flash('Invalid username or password', 'danger')
        
        return render_template('login.html')

    @app.route('/register', methods=['GET', 'POST'])
    @limiter.limit("3 per minute")
    def register():
        if request.method == 'POST':
            username = request.form['username']
            email = request.form['email']
            password = request.form['password']
            
            # Validate password strength
            is_valid, message = validate_password_strength(password)
            if not is_valid:
                flash(message, 'danger')
                return render_template('register.html')
            
            hashed_password = hash_password(password)
            
            with app.app_context():
                conn = current_app.config['db_connection']
                cur = conn.cursor()
                try:
                    cur.execute("""
                        INSERT INTO users (username, email, hashed_password)
                        VALUES (%s, %s, %s)
                        RETURNING id
                    """, (username, email, hashed_password))
                    user_id = cur.fetchone()[0]
                    conn.commit()
                    
                    log_audit(user_id, 'register', 'New user registration', request.remote_addr)
                    flash('Registration successful! Please log in.', 'success')
                    return redirect(url_for('login'))
                except Exception as e:
                    conn.rollback()
                    flash(f'Error during registration: {str(e)}', 'danger')
                finally:
                    cur.close()
        
        return render_template('register.html')

    @app.route('/dashboard')
    @login_required
    def dashboard():
        user_id = session['user_id']
        passwords = get_user_passwords(user_id)
        
        # Decrypt passwords for display
        decrypted_passwords = []
        for pwd in passwords:
            decrypted = {
                'id': pwd['id'],
                'service': pwd['service'],
                'username': pwd['username'],
                'password': decrypt_password(pwd['password'], current_app.key)
            }
            decrypted_passwords.append(decrypted)
        
        return render_template('dashboard.html', passwords=decrypted_passwords)

    @app.route('/save', methods=['POST'])
    @login_required
    def save():
        service = request.form['service']
        username = request.form['username']
        password = request.form['password']
        
        # Validate password strength
        is_valid, message = validate_password_strength(password)
        if not is_valid:
            flash(message, 'danger')
            return redirect(url_for('dashboard'))
        
        encrypted = encrypt_password(password, current_app.key)
        save_password(service, username, encrypted, session['user_id'])
        
        log_audit(session['user_id'], 'save_password', f'Saved password for service: {service}', request.remote_addr)
        flash('Password saved successfully!', 'success')
        return redirect(url_for('dashboard'))

    @app.route('/delete/<int:id>', methods=['POST'])
    @login_required
    def delete(id):
        delete_password(id, session['user_id'])
        log_audit(session['user_id'], 'delete_password', f'Deleted password with ID: {id}', request.remote_addr)
        flash('Password deleted successfully!', 'success')
        return redirect(url_for('dashboard'))

    @app.route('/edit/<int:id>', methods=['GET', 'POST'])
    @login_required
    def edit(id):
        if request.method == 'POST':
            service = request.form['service']
            username = request.form['username']
            password = request.form['password']
            
            # Validate password strength
            is_valid, message = validate_password_strength(password)
            if not is_valid:
                flash(message, 'danger')
                return redirect(url_for('edit', id=id))
            
            encrypted = encrypt_password(password, current_app.key)
            update_password(id, service, username, encrypted, session['user_id'])
            
            log_audit(session['user_id'], 'update_password', f'Updated password for service: {service}', request.remote_addr)
            flash('Password updated successfully!', 'success')
            return redirect(url_for('dashboard'))
        
        password = get_password(id, session['user_id'])
        if not password:
            flash('Password not found', 'danger')
            return redirect(url_for('dashboard'))
        
        decrypted = {
            'id': password['id'],
            'service': password['service'],
            'username': password['username'],
            'password': decrypt_password(password['password'], current_app.key)
        }
        
        return render_template('edit.html', password=decrypted)

    @app.route('/generate-password')
    @login_required
    def generate_password():
        return {'password': generate_secure_password()}

    @app.route('/logout')
    def logout():
        if 'user_id' in session:
            log_audit(session['user_id'], 'logout', 'User logged out', request.remote_addr)
        session.clear()
        flash('You have been logged out.', 'info')
        return redirect(url_for('login'))

    return app

app = create_app()

if __name__ == '__main__':
    app.run(host="0.0.0.0", debug=app.config['DEBUG'])
