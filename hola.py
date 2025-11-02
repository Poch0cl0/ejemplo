import os
import sqlite3
import shlex
import subprocess

def login(username, password):
    # ✅ Consulta segura con parámetros
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
    user = cursor.fetchone()
    conn.close()

    if user:
        print("Login exitoso!")
    else:
        print("Credenciales inválidas.")

def run_command():
    # ✅ Validación y ejecución segura del comando
    cmd = input("Ingresa un comando permitido (ls, whoami, date): ").strip()
    allowed_cmds = {"ls", "whoami", "date"}
    if cmd in allowed_cmds:
        # Separa los argumentos y ejecuta sin shell
        subprocess.run(shlex.split(cmd), check=True)
    else:
        print("Comando no permitido.")

if __name__ == "__main__":
    u = input("Usuario: ")
    p = input("Contraseña: ")
    login(u, p)
    run_command()
