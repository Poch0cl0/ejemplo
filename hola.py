import os
import sqlite3
import re
import hashlib
import secrets
import logging

# Configuración de logging seguro
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Validación del nombre de usuario (solo letras, números, guiones o guion bajo)
USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")

def hash_password(password: str) -> str:
    """Genera un hash seguro de la contraseña usando SHA-256 y un salt aleatorio."""
    salt = secrets.token_hex(16)
    hashed = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()
    return f"{salt}${hashed}"

def verify_password(stored_hash: str, provided_password: str) -> bool:
    """Verifica si una contraseña coincide con su hash almacenado."""
    try:
        salt, hashed = stored_hash.split("$")
        return hashlib.sha256((salt + provided_password).encode("utf-8")).hexdigest() == hashed
    except ValueError:
        return False

def get_db_connection():
    """Obtiene conexión segura a la base de datos (usando variable de entorno)."""
    db_path = os.getenv("APP_DB_PATH", "secure_app.db")
    return sqlite3.connect(db_path, timeout=10, isolation_level=None)

def register_user(username: str, password: str):
    """Registra un nuevo usuario en la base de datos de forma segura."""
    if not USERNAME_PATTERN.match(username):
        logging.warning("Nombre de usuario no válido.")
        return

    hashed_password = hash_password(password)
    try:
        with get_db_connection() as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password_hash TEXT)"
            )
            conn.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, hashed_password),
            )
        logging.info(f"Usuario '{username}' registrado correctamente.")
    except sqlite3.IntegrityError:
        logging.error("El usuario ya existe.")
    except Exception as e:
        logging.exception(f"Error al registrar usuario: {e}")

def authenticate_user(username: str, password: str) -> bool:
    """Autentica un usuario comparando el hash almacenado con el ingresado."""
    try:
        with get_db_connection() as conn:
            cursor = conn.execute(
                "SELECT password_hash FROM users WHERE username = ?", (username,)
            )
            row = cursor.fetchone()
            if row and verify_password(row[0], password):
                logging.info("Autenticación exitosa.")
                return True
            else:
                logging.warning("Credenciales inválidas.")
                return False
    except Exception as e:
        logging.exception(f"Error durante autenticación: {e}")
        return False

if __name__ == "__main__":
    # Ejemplo de uso
    register_user("user123", "StrongP@ssword1")
    authenticate_user("user123", "StrongP@ssword1")
