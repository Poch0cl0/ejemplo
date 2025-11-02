def safe_sum(a, b):
    """
    Calcula la suma de dos números de forma segura.
    - Valida los tipos de entrada.
    - Evita conversiones automáticas o ejecución de código no confiable.
    """
    if not isinstance(a, (int, float)) or not isinstance(b, (int, float)):
        raise TypeError("Ambos argumentos deben ser numéricos (int o float).")
    return a + b


if __name__ == "__main__":
    try:
        a = float(input("Ingrese el primer número: "))
        b = float(input("Ingrese el segundo número: "))
        print("Resultado seguro:", safe_sum(a, b))
    except ValueError:
        print("⚠️ Error: Debe ingresar solo números válidos.")
    except TypeError as e:
        print("⚠️", e)
