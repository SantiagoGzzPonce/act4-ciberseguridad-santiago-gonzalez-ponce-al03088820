"""VERSION VULNERABLE (solo para demostrar el ataque; escucha solo en 127.0.0.1).

Reproduce el escenario del prompt de IA: API con inyeccion SQL + JWT mal configurado.
  [V1] El SQL se arma concatenando el parametro 'categoria'  -> UNION SELECT.
  [V2] El JWT usa HS256 con un secreto debil de diccionario ("secret").
  [V3] Se acepta alg=none: el servidor confia en el algoritmo que dice el propio token.
  [V4] No se valida exp, aud ni iss; los roles salen del token sin mas control.
  [V5] Los errores devuelven el mensaje de la base de datos.
NO usar fuera del laboratorio. La version corregida es app.py.
"""
import base64
import json
import sqlite3

import jwt
from flask import Flask, jsonify, request

from app import DB_PATH, init_db

WEAK_SECRET = "secret"                                     # [V2]
app = Flask(__name__)


def b64d(part):
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


def decode_insecure(token):
    header = json.loads(b64d(token.split(".")[0]))
    if header.get("alg", "").lower() == "none":            # [V3]
        return json.loads(b64d(token.split(".")[1]))
    return jwt.decode(token, WEAK_SECRET, algorithms=[header["alg"]],
                      options={"verify_exp": False, "verify_aud": False})  # [V4]


@app.post("/login")
def login():
    data = request.get_json(force=True)
    if data.get("usuario") == "invitado" and data.get("password") == "invitado":
        tok = jwt.encode({"sub": "invitado", "rol": "lector"}, WEAK_SECRET, algorithm="HS256")
        return jsonify(token=tok)
    return jsonify(error="credenciales"), 401


@app.get("/api/productos")
def listar():
    try:
        claims = decode_insecure(request.headers.get("Authorization", "")[7:])
    except Exception as e:
        return jsonify(error=str(e)), 401
    categoria = request.args.get("categoria", "redes")
    sql = f"SELECT id, nombre, categoria, precio, stock FROM productos WHERE categoria = '{categoria}'"  # [V1]
    con = sqlite3.connect(DB_PATH)
    try:
        rows = con.execute(sql).fetchall()
    except sqlite3.Error as e:
        return jsonify(error=str(e), sql=sql), 500         # [V5]
    finally:
        con.close()
    return jsonify(usuario=claims.get("sub"), rol=claims.get("rol"), datos=rows)


@app.delete("/api/productos/<int:pid>")
def borrar(pid):
    claims = decode_insecure(request.headers.get("Authorization", "")[7:])
    if claims.get("rol") != "admin":                         # el rol viene del token
        return jsonify(error="solo admin"), 403
    return jsonify(borrado=pid, por=claims.get("sub"))


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5003)
