import os
import pickle
import sqlite3
from flask import Flask, request, render_template_string

app = Flask(__name__)

# Vulnerabilidad 1: Clave secreta hardcodeada
SECRET_KEY = "mi_clave_super_secreta_123"
API_KEY = "sk-1234567890abcdef"

# Vulnerabilidad 2: SQL Injection
def buscar_usuario(username):
    conn = sqlite3.connect('usuarios.db')
    cursor = conn.cursor()
    # Concatenación directa de strings - SQL Injection
    query = f"SELECT * FROM usuarios WHERE username = '{username}'"
    cursor.execute(query)
    resultado = cursor.fetchall()
    conn.close()
    return resultado

# Vulnerabilidad 3: Command Injection
def procesar_archivo(filename):
    # Ejecución de comandos del sistema sin validación
    os.system(f"cat {filename}")
    return "Archivo procesado"

# Vulnerabilidad 4: Insecure Deserialization
def cargar_datos(data):
    # Pickle puede ejecutar código arbitrario
    obj = pickle.loads(data)
    return obj

# Vulnerabilidad 5: Path Traversal
@app.route('/leer_archivo')
def leer_archivo():
    archivo = request.args.get('archivo')
    # Sin validación del path
    with open(archivo, 'r') as f:
        contenido = f.read()
    return contenido

# Vulnerabilidad 6: Server-Side Template Injection (SSTI)
@app.route('/saludo')
def saludo():
    nombre = request.args.get('nombre', 'Invitado')
    # Renderizado inseguro de templates
    template = f"<h1>Hola {nombre}!</h1>"
    return render_template_string(template)

# Vulnerabilidad 7: Hardcoded Credentials
def conectar_db():
    usuario = "admin"
    password = "admin123"
    host = "192.168.1.100"
    return f"mysql://{usuario}:{password}@{host}/midb"

# Vulnerabilidad 8: Weak Cryptography
def cifrar_password(password):
    # MD5 es inseguro para passwords
    import hashlib
    return hashlib.md5(password.encode()).hexdigest()

# Vulnerabilidad 9: Information Disclosure
@app.route('/error')
def error_handler():
    try:
        resultado = 1 / 0
    except Exception as e:
        # Exposición de información sensible en errores
        return f"Error: {str(e)}, Stack: {e.__traceback__}"

# Vulnerabilidad 10: Missing Authentication
@app.route('/admin/delete_user')
def delete_user():
    user_id = request.args.get('id')
    # No hay verificación de autenticación
    conn = sqlite3.connect('usuarios.db')
    cursor = conn.cursor()
    cursor.execute(f"DELETE FROM usuarios WHERE id = {user_id}")
    conn.commit()
    conn.close()
    return "Usuario eliminado"

if __name__ == '__main__':
    # Vulnerabilidad 11: Debug mode en producción
    app.run(debug=True, host='0.0.0.0', port=5000)