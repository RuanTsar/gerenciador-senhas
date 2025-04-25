import psycopg2
import os
from contextlib import closing

def get_db_connection():
    return psycopg2.connect(
        host=os.environ.get("DB_HOST"),
        port=os.environ.get("DB_PORT", 5432),
        database=os.environ.get("DB_NAME"),
        user=os.environ.get("DB_USER"),
        password=os.environ.get("DB_PASSWORD")
    )



def init_db():
    with closing(get_db_connection()) as conn:
        with conn.cursor() as cursor:
            # Criação da tabela de usuários
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    hashed_password TEXT NOT NULL,
                    data_criacao TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Criação da tabela de senhas (com FK)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS passwords (
                    id SERIAL PRIMARY KEY,
                    service TEXT NOT NULL,
                    username TEXT NOT NULL,
                    password TEXT NOT NULL,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE
                )
            """)

            conn.commit()

# ====================
# CRUD com user_id
# ====================

def save_password(service, username, encrypted_password, user_id):
    with closing(get_db_connection()) as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                "INSERT INTO passwords (service, username, password, user_id) VALUES (%s, %s, %s, %s)",
                (service, username, encrypted_password, user_id)
            )
            conn.commit()

def update_password(id, service, username, encrypted_password, user_id):
    with closing(get_db_connection()) as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                "UPDATE passwords SET service = %s, username = %s, password = %s WHERE id = %s AND user_id = %s",
                (service, username, encrypted_password, id, user_id)
            )
            conn.commit()

def delete_password(id, user_id):
    with closing(get_db_connection()) as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                "DELETE FROM passwords WHERE id = %s AND user_id = %s",
                (id, user_id)
            )
            conn.commit()

def get_passwords(user_id):
    with closing(get_db_connection()) as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT id, service, username, password FROM passwords WHERE user_id = %s",
                (user_id,)
            )
            return cursor.fetchall()
