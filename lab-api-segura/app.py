"""API de inventario protegida con OAuth 2.0 (client credentials) + JWT RS256.

Controles implementados (Paso 2 de la actividad):
  [C1] Servidor de autorizacion OAuth 2.0: POST /oauth/token (grant client_credentials,
       autenticacion del cliente con HTTP Basic, secretos guardados como hash PBKDF2).
  [C2] JWT firmado con RS256; la API solo acepta ese algoritmo (bloquea alg=none y la
       confusion RS256->HS256) y exige exp, iat, nbf, iss, aud, sub, jti.
  [C3] Autorizacion por scopes: productos:read / productos:write (403 si falta).
  [C4] Validacion de entradas por lista blanca (tipo, longitud, regex) + consultas SQL
       parametrizadas: el dato nunca se concatena en el SQL.
  [C5] Rate limiting de ventana deslizante: 100 solicitudes/minuto por cliente (o IP),
       respuesta 429 + Retry-After y cabeceras X-RateLimit-*.
  [C6] Errores genericos (sin trazas ni SQL), cabeceras de seguridad y limite de tamano.
"""
import base64
import hashlib
import hmac
import os
import re
import sqlite3
import threading
import time
import uuid
from collections import defaultdict, deque
from functools import wraps
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask, g, jsonify, request

BASE = Path(__file__).resolve().parent
ISSUER = os.environ.get("JWT_ISSUER", "https://auth.act4.local")
AUDIENCE = os.environ.get("JWT_AUDIENCE", "api-inventario")
TOKEN_TTL = int(os.environ.get("TOKEN_TTL", "900"))            # 15 minutos
RATE_LIMIT = int(os.environ.get("RATE_LIMIT", "100"))           # solicitudes
RATE_WINDOW = int(os.environ.get("RATE_WINDOW", "60"))          # segundos
DB_PATH = os.environ.get("DB_PATH", str(BASE / "inventario.db"))
KEY_PATH = Path(os.environ.get("KEY_PATH", str(BASE / "keys" / "private.pem")))

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024                    # [C6] 16 KB maximo


# --------------------------------------------------------------------------- llaves
def load_private_key():
    if KEY_PATH.exists():
        return serialization.load_pem_private_key(KEY_PATH.read_bytes(), password=None)
    KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    KEY_PATH.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    os.chmod(KEY_PATH, 0o600)
    return key


PRIVATE_KEY = load_private_key()
PUBLIC_KEY = PRIVATE_KEY.public_key()
KID = hashlib.sha256(PUBLIC_KEY.public_bytes(
    serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()[:16]


# ------------------------------------------------------------------------- clientes
def hash_secret(secret: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac("sha256", secret.encode(), salt, 200_000).hex()


def load_clients():
    """Clientes OAuth registrados. Los secretos vienen de variables de entorno (.env)."""
    clients = {}
    for cid, env, scopes in (
        ("app-lectura", "CLIENT_LECTURA_SECRET", {"productos:read"}),
        ("app-admin", "CLIENT_ADMIN_SECRET", {"productos:read", "productos:write"}),
    ):
        secret = os.environ.get(env)
        if not secret:
            continue
        salt = os.urandom(16)
        clients[cid] = {"salt": salt, "hash": hash_secret(secret, salt), "scopes": scopes}
    return clients


CLIENTS = load_clients()


# ------------------------------------------------------------------------ base de datos
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    con = sqlite3.connect(DB_PATH)
    con.executescript("""
        CREATE TABLE IF NOT EXISTS productos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nombre TEXT NOT NULL,
            categoria TEXT NOT NULL,
            precio REAL NOT NULL,
            stock INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY, email TEXT, password_hash TEXT);
    """)
    if con.execute("SELECT COUNT(*) FROM productos").fetchone()[0] == 0:
        con.executemany(
            "INSERT INTO productos (nombre, categoria, precio, stock) VALUES (?,?,?,?)",
            [("Router VPN", "redes", 2499.0, 12), ("Switch 24p", "redes", 3899.0, 5),
             ("Camara IP", "iot", 899.0, 40), ("Sensor de humo", "iot", 450.0, 25),
             ("Licencia antivirus", "software", 699.0, 100)])
        # Tabla "sensible": si existiera SQLi, UNION SELECT la expondria.
        con.execute("INSERT INTO usuarios VALUES (1, 'admin@act4.local', 'pbkdf2$...')")
    con.commit()
    con.close()


# --------------------------------------------------------------------- rate limiting
class SlidingWindowLimiter:
    """[C5] Ventana deslizante en memoria (para varios workers usar Redis)."""

    def __init__(self, limit, window):
        self.limit, self.window = limit, window
        self.hits = defaultdict(deque)
        self.lock = threading.Lock()

    def check(self, key):
        now = time.monotonic()
        with self.lock:
            q = self.hits[key]
            while q and q[0] <= now - self.window:
                q.popleft()
            if len(q) >= self.limit:
                retry = int(q[0] + self.window - now) + 1
                return False, 0, retry
            q.append(now)
            return True, self.limit - len(q), 0

    def reset(self):
        with self.lock:
            self.hits.clear()


limiter = SlidingWindowLimiter(RATE_LIMIT, RATE_WINDOW)


def client_key():
    """Cuenta por el 'sub' de un JWT con firma valida; si no hay token valido, por IP.
    (Si se usara el sub sin verificar, un atacante inventaria un sub nuevo por solicitud
    para evadir el limite.)"""
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        try:
            sub = jwt.decode(auth[7:], PUBLIC_KEY, algorithms=["RS256"], audience=AUDIENCE,
                             issuer=ISSUER).get("sub")
            if isinstance(sub, str) and len(sub) < 64:
                return "sub:" + sub
        except jwt.PyJWTError:
            pass
    return "ip:" + (request.remote_addr or "?")


@app.before_request
def apply_rate_limit():
    if request.path == "/health":
        return None
    ok, remaining, retry = limiter.check(client_key())
    g.rl_remaining = remaining
    if not ok:
        resp = jsonify(error="rate_limited",
                       detail=f"Limite de {RATE_LIMIT} solicitudes por {RATE_WINDOW} s")
        resp.status_code = 429
        resp.headers["Retry-After"] = str(retry)
        resp.headers["X-RateLimit-Limit"] = str(RATE_LIMIT)
        resp.headers["X-RateLimit-Remaining"] = "0"
        return resp
    return None


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    if resp.status_code != 429 and hasattr(g, "rl_remaining"):
        resp.headers["X-RateLimit-Limit"] = str(RATE_LIMIT)
        resp.headers["X-RateLimit-Remaining"] = str(g.rl_remaining)
    return resp


# ------------------------------------------------------------- OAuth 2.0 + emision JWT
def oauth_error(code, desc, status=400):
    resp = jsonify(error=code, error_description=desc)
    resp.status_code = status
    if status == 401:
        resp.headers["WWW-Authenticate"] = 'Basic realm="oauth"'
    return resp


@app.post("/oauth/token")
def token():
    """[C1] RFC 6749 sec. 4.4 - Client Credentials Grant."""
    if request.form.get("grant_type") != "client_credentials":
        return oauth_error("unsupported_grant_type", "Solo client_credentials")
    auth = request.authorization
    if not auth or auth.type != "basic":
        return oauth_error("invalid_client", "Autenticacion del cliente requerida", 401)
    client = CLIENTS.get(auth.username or "")
    # Comparacion en tiempo constante; si el cliente no existe se calcula igual un hash.
    salt = client["salt"] if client else b"\0" * 16
    expected = client["hash"] if client else "0" * 64
    if not hmac.compare_digest(hash_secret(auth.password or "", salt), expected) or not client:
        return oauth_error("invalid_client", "Credenciales invalidas", 401)

    requested = set((request.form.get("scope") or " ".join(client["scopes"])).split())
    if not requested <= client["scopes"]:
        return oauth_error("invalid_scope", "Scope no permitido para este cliente")

    now = int(time.time())
    claims = {"iss": ISSUER, "aud": AUDIENCE, "sub": auth.username, "iat": now, "nbf": now,
              "exp": now + TOKEN_TTL, "jti": str(uuid.uuid4()), "scope": " ".join(sorted(requested))}
    access = jwt.encode(claims, PRIVATE_KEY, algorithm="RS256", headers={"kid": KID})
    return jsonify(access_token=access, token_type="Bearer", expires_in=TOKEN_TTL,
                   scope=claims["scope"])


@app.get("/.well-known/jwks.json")
def jwks():
    nums = PUBLIC_KEY.public_numbers()

    def b64(n):
        return base64.urlsafe_b64encode(n.to_bytes((n.bit_length() + 7) // 8, "big")).rstrip(b"=").decode()

    return jsonify(keys=[{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": KID,
                          "n": b64(nums.n), "e": b64(nums.e)}])


def require_scope(scope):
    """[C2][C3] Valida el JWT y el scope antes de entrar al endpoint."""
    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            auth = request.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                return _unauth("invalid_request", "Falta el token Bearer")
            try:
                claims = jwt.decode(
                    auth[7:], PUBLIC_KEY,
                    algorithms=["RS256"],             # lista blanca: nada de none/HS256
                    audience=AUDIENCE, issuer=ISSUER, leeway=30,
                    options={"require": ["exp", "iat", "nbf", "iss", "aud", "sub", "jti"]})
            except jwt.ExpiredSignatureError:
                return _unauth("invalid_token", "Token expirado")
            except jwt.PyJWTError:
                return _unauth("invalid_token", "Token invalido")
            if scope not in claims.get("scope", "").split():
                resp = jsonify(error="insufficient_scope", required=scope)
                resp.status_code = 403
                return resp
            g.claims = claims
            return fn(*args, **kwargs)
        return wrapper
    return deco


def _unauth(code, desc):
    resp = jsonify(error=code, error_description=desc)
    resp.status_code = 401
    resp.headers["WWW-Authenticate"] = f'Bearer error="{code}"'
    return resp


# --------------------------------------------------------------- validacion de entradas
CATEGORIAS = {"redes", "iot", "software"}
NOMBRE_RE = re.compile(r"^[A-Za-z0-9ÁÉÍÓÚÑáéíóúñ .\-]{2,60}$")
ID_RE = re.compile(r"^[1-9][0-9]{0,8}$")


class ValidationError(Exception):
    pass


def validar_producto(data):
    """[C4] Lista blanca: solo los campos esperados, con tipo, rango y formato."""
    if not isinstance(data, dict):
        raise ValidationError("El cuerpo debe ser un objeto JSON")
    extra = set(data) - {"nombre", "categoria", "precio", "stock"}
    if extra:
        raise ValidationError(f"Campos no permitidos: {sorted(extra)}")
    nombre, categoria = data.get("nombre"), data.get("categoria")
    precio, stock = data.get("precio"), data.get("stock")
    if not isinstance(nombre, str) or not NOMBRE_RE.fullmatch(nombre):
        raise ValidationError("nombre: 2-60 caracteres alfanumericos, espacio, punto o guion")
    if categoria not in CATEGORIAS:
        raise ValidationError(f"categoria: una de {sorted(CATEGORIAS)}")
    if isinstance(precio, bool) or not isinstance(precio, (int, float)) or not 0 < precio <= 1_000_000:
        raise ValidationError("precio: numero entre 0 y 1,000,000")
    if isinstance(stock, bool) or not isinstance(stock, int) or not 0 <= stock <= 100_000:
        raise ValidationError("stock: entero entre 0 y 100,000")
    return nombre.strip(), categoria, float(precio), stock


@app.errorhandler(ValidationError)
def on_validation(err):
    return jsonify(error="validation_error", detail=str(err)), 400


@app.errorhandler(413)
def on_too_large(_e):
    return jsonify(error="payload_too_large"), 413


@app.errorhandler(Exception)
def on_error(_e):
    app.logger.exception("Error no controlado")
    return jsonify(error="internal_error"), 500               # [C6] sin detalles


# ----------------------------------------------------------------------- endpoints
@app.get("/health")
def health():
    return jsonify(status="ok")


@app.get("/api/productos")
@require_scope("productos:read")
def listar():
    categoria = request.args.get("categoria")
    if categoria is not None and categoria not in CATEGORIAS:
        raise ValidationError(f"categoria: una de {sorted(CATEGORIAS)}")
    sql = "SELECT id, nombre, categoria, precio, stock FROM productos"
    params = ()
    if categoria:
        sql += " WHERE categoria = ?"                          # parametro, no concatenacion
        params = (categoria,)
    rows = get_db().execute(sql + " ORDER BY id", params).fetchall()
    return jsonify([dict(r) for r in rows])


@app.get("/api/productos/<pid>")
@require_scope("productos:read")
def obtener(pid):
    if not ID_RE.fullmatch(pid):
        raise ValidationError("id: entero positivo")
    row = get_db().execute(
        "SELECT id, nombre, categoria, precio, stock FROM productos WHERE id = ?", (int(pid),)).fetchone()
    if row is None:
        return jsonify(error="not_found"), 404
    return jsonify(dict(row))


@app.post("/api/productos")
@require_scope("productos:write")
def crear():
    if not request.is_json:
        raise ValidationError("Content-Type debe ser application/json")
    nombre, categoria, precio, stock = validar_producto(request.get_json(silent=True))
    db = get_db()
    cur = db.execute(
        "INSERT INTO productos (nombre, categoria, precio, stock) VALUES (?,?,?,?)",
        (nombre, categoria, precio, stock))
    db.commit()
    return jsonify(id=cur.lastrowid, nombre=nombre, categoria=categoria,
                   precio=precio, stock=stock, creado_por=g.claims["sub"]), 201


init_db()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5002")))
