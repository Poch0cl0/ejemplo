#!/usr/bin/env python3
"""
NotasSeguras - ejemplo seguro (CLI) para registrar usuarios y guardar notas.

Buenas prácticas incluidas:
- Hash de contraseñas con PBKDF2-HMAC-SHA256 + salt por usuario.
- Parámetros en consultas SQLite (no concatenación de strings).
- Validación de entradas (usuario y contraseña).
- Uso de context managers para recursos.
- Comparación en tiempo constante para hashes.
- Logging en lugar de prints para eventos importantes.
- Tipado y docstrings.
"""

from __future__ import annotations
import argparse
import sqlite3
import os
import re
import hmac
import hashlib
import logging
from typing import Optional, Iterable, Tuple

# Configuración de logging (no exponer información sensible)
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

DB_PATH = "notasseguras.db"
PBKDF2_ITERATIONS = 200_000  # suficientemente alto para dificultad computacional
SALT_BYTES = 16
HASH_LEN = 32  # 256 bits


# ---------- Utilidades criptográficas seguras ----------

def generate_salt() -> bytes:
    """Genera un salt criptográficamente seguro."""
    return os.urandom(SALT_BYTES)


def hash_password(password: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes:
    """
    Deriva una clave segura desde la contraseña usando PBKDF2-HMAC-SHA256.
    Devuelve bytes (el hash).
    """
    if not isinstance(password, str):
        raise TypeError("password debe ser str")
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=HASH_LEN)


def verify_password(password: str, salt: bytes, expected_hash: bytes, iterations: int = PBKDF2_ITERATIONS) -> bool:
    """Verifica la contraseña usando comparación en tiempo constante."""
    candidate = hash_password(password, salt, iterations)
    return hmac.compare_digest(candidate, expected_hash)


# ---------- Validaciones ----------

USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{3,30}$")  # permitir solo caracteres seguros, longitud razonable
MIN_PASSWORD_LEN = 8


def validate_username(username: str) -> None:
    if not USERNAME_RE.match(username):
        raise ValueError("Usuario inválido. Solo letras, números, ., _ y -; longitud 3-30.")


def validate_password(password: str) -> None:
    if len(password) < MIN_PASSWORD_LEN:
        raise ValueError(f"Contraseña muy corta. Mínimo {MIN_PASSWORD_LEN} caracteres.")


# ---------- Base de datos ----------

def get_connection(path: str =
