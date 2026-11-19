"""Crea .env con secretos aleatorios para los clientes OAuth (permisos 600)."""
import os
import secrets
from pathlib import Path

env = Path(__file__).with_name(".env")
if env.exists():
    raise SystemExit(".env ya existe; borralo si quieres regenerarlo")
env.write_text(
    f"CLIENT_LECTURA_SECRET={secrets.token_urlsafe(32)}\n"
    f"CLIENT_ADMIN_SECRET={secrets.token_urlsafe(32)}\n"
    "JWT_ISSUER=https://auth.act4.local\nJWT_AUDIENCE=api-inventario\n"
    "TOKEN_TTL=900\nRATE_LIMIT=100\nRATE_WINDOW=60\n")
os.chmod(env, 0o600)
print("Creado", env)
