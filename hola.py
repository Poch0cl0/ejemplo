import os

def safe_read_file(filename):
    """
    Lee un archivo de texto de forma segura.
    - Solo permite archivos dentro del directorio actual.
    - Evita rutas peligrosas o archivos binarios.
    """
    base_dir = os.getcwd()
    file_path = os.path.abspath(os.path.join(base_dir, filename))

    # Evita acceder fuera del directorio permitido
    if not file_path.startswith(base_dir):
        raise PermissionError("Acceso denegado: ruta no permitida.")

    # Verifica extensión segura
    if not filename.lower().endswith(".txt"):
        raise ValueError("Solo se permiten archivos .txt")

    with open(file_path, "r", encoding="utf-8") as f:
        return f.read()


if __name__ == "__main__":
    try:
        name = input("Ingrese el nombre del archivo .txt: ").strip()
        print("\nContenido del archivo:\n")
        print(safe_read_file(name))
    except FileNotFoundError:
        print("⚠️ Archivo no encontrado.")
    except (PermissionError, ValueError) as e:
        print(f"⚠️ {e}")
    except Exception as e:
        print(f"⚠️ Error inesperado: {e}")
