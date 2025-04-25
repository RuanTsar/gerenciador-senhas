from cryptography.fernet import Fernet
import os

KEY_FILE = "key.key"

def load_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as key_file:
            key_file.write(key)
    else:
        with open(KEY_FILE, "rb") as key_file:
            key = key_file.read()
    return key


def encrypt_password(password, key):
    # Criptografa e retorna como string (para salvar no PostgreSQL como texto)
    return Fernet(key).encrypt(password.encode()).decode()

def decrypt_password(encrypted_password, key):
    # Converte de volta para bytes e descriptografa
    return Fernet(key).decrypt(encrypted_password.encode()).decode()
