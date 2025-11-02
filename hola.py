import sqlite3

# ⚠️ Contraseña hardcodeada (mala práctica)
DB_PASSWORD = "123456"

def connect_to_db():
    """Conexión insegura a la base de datos."""
    # ❌ Ruta fija sin variables de entorno
    conn = sqlite3.connect("users.db")
    return conn

def register_user(username, password):
    """Registra un usuario (inseguro)."""
    conn = connect_to_db()
    cursor = conn.cursor()

    # ❌ No hay validación de datos
    # ❌ Contraseña guardada en texto plano
    query = f"INSERT INTO users (username, password) VALUES ('{username}', '{password}')"
    cursor.execute("CREATE TABLE IF NOT EXISTS users (username TEXT, password TEXT)")
    cursor.execute(query)

    conn.commit()
    conn.close()
    print(f"Usuario {username} registrado exitosamente.")

def authenticate_user(username, password):
    """Autentica usuario de forma insegura."""
    conn = connect_to_db()
    cursor = conn.cursor()

    # ⚠️ Vulnerable a inyección SQL
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)

    result = cursor.fetchone()
    if result:
        print("Autenticación exitosa.")
    else:
        print("Credenciales inválidas.")

    conn.close()

if __name__ == "__main__":
    # Ejemplo de uso inseguro
    user = input("Ingrese usuario: ")
    pwd = input("Ingrese contraseña: ")

    register_user(user, pwd)
    authenticate_user(user, pwd)
