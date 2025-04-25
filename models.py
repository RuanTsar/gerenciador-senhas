import psycopg2
from psycopg2.extras import DictCursor
from contextlib import contextmanager

@contextmanager
def get_db_connection(get_db_func):
    """Get a database connection with proper error handling"""
    conn = None
    try:
        conn = get_db_func()
        yield conn
    except psycopg2.Error as e:
        raise
    finally:
        if conn:
            conn.close()

def init_db(get_db_func):
    """Initialize the database with required tables"""
    conn = get_db_func()
    try:
        with conn.cursor() as cur:
            # Create users table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(50) UNIQUE NOT NULL,
                    email VARCHAR(120) UNIQUE NOT NULL,
                    hashed_password VARCHAR(255) NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP
                )
            """)
            
            # Create passwords table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS passwords (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                    service VARCHAR(100) NOT NULL,
                    username VARCHAR(100) NOT NULL,
                    password TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    notes TEXT
                )
            """)
            
            # Create audit_log table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                    action VARCHAR(50) NOT NULL,
                    details TEXT,
                    ip_address VARCHAR(45),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            conn.commit()
    except Exception as e:
        raise
    finally:
        conn.close()

def save_password(service, username, encrypted_password, user_id, get_db_func):
    """Save a new password entry"""
    with get_db_connection(get_db_func) as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO passwords (service, username, password, user_id)
                VALUES (%s, %s, %s, %s)
                RETURNING id
            """, (service, username, encrypted_password, user_id))
            conn.commit()
            return cur.fetchone()[0]

def get_password(password_id, user_id, get_db_func):
    """Get a specific password entry"""
    with get_db_connection(get_db_func) as conn:
        with conn.cursor(cursor_factory=DictCursor) as cur:
            cur.execute("""
                SELECT * FROM passwords
                WHERE id = %s AND user_id = %s
            """, (password_id, user_id))
            return cur.fetchone()

def update_password(password_id, service, username, encrypted_password, user_id, get_db_func):
    """Update an existing password entry"""
    with get_db_connection(get_db_func) as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE passwords
                SET service = %s, username = %s, password = %s, updated_at = CURRENT_TIMESTAMP
                WHERE id = %s AND user_id = %s
            """, (service, username, encrypted_password, password_id, user_id))
            conn.commit()

def delete_password(password_id, user_id, get_db_func):
    """Delete a password entry"""
    with get_db_connection(get_db_func) as conn:
        with conn.cursor() as cur:
            cur.execute("""
                DELETE FROM passwords
                WHERE id = %s AND user_id = %s
            """, (password_id, user_id))
            conn.commit()

def get_user_passwords(user_id, get_db_func):
    """Get all passwords for a user"""
    with get_db_connection(get_db_func) as conn:
        with conn.cursor(cursor_factory=DictCursor) as cur:
            cur.execute("""
                SELECT * FROM passwords
                WHERE user_id = %s
                ORDER BY service
            """, (user_id,))
            return cur.fetchall()

def log_audit(user_id, action, details, ip_address, get_db_func):
    """Log an audit event"""
    with get_db_connection(get_db_func) as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO audit_log (user_id, action, details, ip_address)
                VALUES (%s, %s, %s, %s)
            """, (user_id, action, details, ip_address))
            conn.commit() 