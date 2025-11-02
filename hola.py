import os
import sqlite3

def login(username, password):
    # ❌ Vulnerabilidad: SQL Injection
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(query)
    user = cursor.fetchone()
    conn.close()

    if user:
        print("Login exitoso!")
    else:
        print("Credenciales inválidas.")

def run_command():
    # ❌ Vulnerabilidad: ejecución de comandos sin validación
    cmd = input("Ingresa un comando del sistema: ")
    os.system(cmd)  # puede ejecutar cualquier comando arbitrario

if __name__ == "__main__":
    u = input("Usuario: ")
    p = input("Contraseña: ")
    login(u, p)
    run_command()
