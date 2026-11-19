"""Pruebas de la API segura (app.py) y demostracion del ataque contra app_vulnerable.py."""
import base64
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

TMP = tempfile.mkdtemp()
os.environ.update(
    DB_PATH=os.path.join(TMP, "test.db"), KEY_PATH=os.path.join(TMP, "k.pem"),
    CLIENT_LECTURA_SECRET="lectura-test-0123456789", CLIENT_ADMIN_SECRET="admin-test-0123456789",
    RATE_LIMIT="100", RATE_WINDOW="60")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import jwt  # noqa: E402

import app as api  # noqa: E402
import app_vulnerable as vuln  # noqa: E402


def basic(user, pwd):
    return {"Authorization": "Basic " + base64.b64encode(f"{user}:{pwd}".encode()).decode()}


def b64(obj):
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


class Base(unittest.TestCase):
    def setUp(self):
        api.limiter.reset()
        self.c = api.app.test_client()

    def token(self, client="app-lectura", secret="lectura-test-0123456789", scope=None):
        data = {"grant_type": "client_credentials"}
        if scope:
            data["scope"] = scope
        r = self.c.post("/oauth/token", data=data, headers=basic(client, secret))
        self.assertEqual(r.status_code, 200, r.get_json())
        return r.get_json()["access_token"]

    def get(self, path, tok):
        return self.c.get(path, headers={"Authorization": "Bearer " + tok})


class TestOAuthJWT(Base):
    def test_01_token_rs256_con_claims(self):
        tok = self.token()
        self.assertEqual(jwt.get_unverified_header(tok)["alg"], "RS256")
        claims = jwt.decode(tok, options={"verify_signature": False})
        for c in ("iss", "aud", "sub", "exp", "iat", "nbf", "jti", "scope"):
            self.assertIn(c, claims)
        self.assertLessEqual(claims["exp"] - claims["iat"], 900)

    def test_02_secreto_incorrecto_401(self):
        r = self.c.post("/oauth/token", data={"grant_type": "client_credentials"},
                        headers=basic("app-lectura", "mal"))
        self.assertEqual(r.status_code, 401)

    def test_03_grant_no_soportado(self):
        r = self.c.post("/oauth/token", data={"grant_type": "password"},
                        headers=basic("app-lectura", "lectura-test-0123456789"))
        self.assertEqual(r.get_json()["error"], "unsupported_grant_type")

    def test_04_scope_no_permitido(self):
        r = self.c.post("/oauth/token", data={"grant_type": "client_credentials",
                                              "scope": "productos:write"},
                        headers=basic("app-lectura", "lectura-test-0123456789"))
        self.assertEqual(r.get_json()["error"], "invalid_scope")

    def test_05_sin_token_401(self):
        self.assertEqual(self.c.get("/api/productos").status_code, 401)

    def test_06_token_valido_200(self):
        r = self.get("/api/productos", self.token())
        self.assertEqual(r.status_code, 200)
        self.assertGreaterEqual(len(r.get_json()), 5)

    def test_07_alg_none_rechazado(self):
        claims = jwt.decode(self.token(), options={"verify_signature": False})
        forged = b64({"alg": "none", "typ": "JWT"}) + "." + b64(claims) + "."
        self.assertEqual(self.get("/api/productos", forged).status_code, 401)

    def test_08_confusion_hs256_con_llave_publica(self):
        pem = api.PUBLIC_KEY.public_bytes(api.serialization.Encoding.PEM,
                                          api.serialization.PublicFormat.SubjectPublicKeyInfo)
        claims = jwt.decode(self.token(), options={"verify_signature": False})
        forged = (b64({"alg": "HS256", "typ": "JWT"}) + "." + b64(claims))
        import hashlib
        import hmac
        sig = base64.urlsafe_b64encode(hmac.new(pem, forged.encode(), hashlib.sha256).digest()).rstrip(b"=").decode()
        self.assertEqual(self.get("/api/productos", forged + "." + sig).status_code, 401)

    def test_09_firma_alterada(self):
        h, p, s = self.token().split(".")
        claims = json.loads(base64.urlsafe_b64decode(p + "=="))
        claims["scope"] = "productos:read productos:write"
        self.assertEqual(self.get("/api/productos", f"{h}.{b64(claims)}.{s}").status_code, 401)

    def test_10_token_expirado(self):
        now = int(time.time())
        tok = jwt.encode({"iss": api.ISSUER, "aud": api.AUDIENCE, "sub": "x", "iat": now - 2000,
                          "nbf": now - 2000, "exp": now - 1000, "jti": "1", "scope": "productos:read"},
                         api.PRIVATE_KEY, algorithm="RS256")
        r = self.get("/api/productos", tok)
        self.assertEqual(r.status_code, 401)
        self.assertIn("expirado", r.get_json()["error_description"])

    def test_11_audiencia_incorrecta(self):
        now = int(time.time())
        tok = jwt.encode({"iss": api.ISSUER, "aud": "otra-api", "sub": "x", "iat": now, "nbf": now,
                          "exp": now + 60, "jti": "1", "scope": "productos:read"},
                         api.PRIVATE_KEY, algorithm="RS256")
        self.assertEqual(self.get("/api/productos", tok).status_code, 401)

    def test_12_scope_insuficiente_403(self):
        r = self.c.post("/api/productos", json={"nombre": "X1", "categoria": "iot", "precio": 1, "stock": 1},
                        headers={"Authorization": "Bearer " + self.token()})
        self.assertEqual(r.status_code, 403)

    def test_13_jwks_publica(self):
        k = self.c.get("/.well-known/jwks.json").get_json()["keys"][0]
        self.assertEqual((k["kty"], k["alg"]), ("RSA", "RS256"))
        self.assertNotIn("d", k)                     # nunca la parte privada


class TestValidacion(Base):
    PAYLOADS = ["redes' OR '1'='1", "redes' UNION SELECT id,email,password_hash,1,1 FROM usuarios--",
                "1; DROP TABLE productos", "' OR 1=1--", "redes%27", "<script>alert(1)</script>"]

    def test_20_sqli_en_query_string_400(self):
        tok = self.token()
        for p in self.PAYLOADS:
            r = self.c.get("/api/productos", query_string={"categoria": p},
                           headers={"Authorization": "Bearer " + tok})
            self.assertEqual(r.status_code, 400, p)
            self.assertNotIn("admin@", r.get_data(as_text=True))

    def test_21_sqli_en_ruta_400(self):
        tok = self.token()
        for p in ["1 OR 1=1", "1'--", "0", "-1", "1 UNION SELECT 1"]:
            self.assertEqual(self.get(f"/api/productos/{p}", tok).status_code, 400, p)

    def test_22_post_valido_201(self):
        tok = self.token("app-admin", "admin-test-0123456789")
        r = self.c.post("/api/productos", json={"nombre": "Firewall pfSense", "categoria": "redes",
                                                "precio": 5200, "stock": 3},
                        headers={"Authorization": "Bearer " + tok})
        self.assertEqual(r.status_code, 201, r.get_json())

    def test_23_post_invalido_400(self):
        tok = self.token("app-admin", "admin-test-0123456789")
        malos = [{"nombre": "x'); DROP TABLE productos;--", "categoria": "redes", "precio": 1, "stock": 1},
                 {"nombre": "Ok", "categoria": "redes", "precio": -5, "stock": 1},
                 {"nombre": "Ok", "categoria": "armas", "precio": 1, "stock": 1},
                 {"nombre": "Ok", "categoria": "redes", "precio": 1, "stock": 1, "rol": "admin"},
                 {"nombre": "Ok", "categoria": "redes", "precio": "1", "stock": True}]
        for body in malos:
            r = self.c.post("/api/productos", json=body, headers={"Authorization": "Bearer " + tok})
            self.assertEqual(r.status_code, 400, body)

    def test_24_payload_grande_413(self):
        tok = self.token("app-admin", "admin-test-0123456789")
        r = self.c.post("/api/productos", data="x" * 20000, content_type="application/json",
                        headers={"Authorization": "Bearer " + tok})
        self.assertEqual(r.status_code, 413)


class TestRateLimit(Base):
    def test_30_limite_100_por_minuto(self):
        tok = self.token()                           # la solicitud de token cuenta por IP
        codes = [self.get("/api/productos", tok).status_code for _ in range(101)]
        self.assertEqual(codes[:100], [200] * 100)
        self.assertEqual(codes[100], 429)
        r = self.get("/api/productos", tok)
        self.assertEqual(r.status_code, 429)
        self.assertGreater(int(r.headers["Retry-After"]), 0)
        self.assertEqual(r.headers["X-RateLimit-Remaining"], "0")

    def test_31_limite_por_cliente(self):
        tok_a = self.token()
        tok_b = self.token("app-admin", "admin-test-0123456789")
        for _ in range(100):
            self.get("/api/productos", tok_a)
        self.assertEqual(self.get("/api/productos", tok_a).status_code, 429)
        self.assertEqual(self.get("/api/productos", tok_b).status_code, 200)

    def test_33_sub_falsificado_no_evade_limite(self):
        for i in range(100):
            fake = b64({"alg": "none"}) + "." + b64({"sub": f"bot{i}"}) + "."
            self.get("/api/productos", fake)
        fake = b64({"alg": "none"}) + "." + b64({"sub": "bot-nuevo"}) + "."
        self.assertEqual(self.get("/api/productos", fake).status_code, 429)

    def test_32_ventana_se_libera(self):
        lim = api.SlidingWindowLimiter(3, 1)
        self.assertTrue(all(lim.check("k")[0] for _ in range(3)))
        self.assertFalse(lim.check("k")[0])
        time.sleep(1.1)
        self.assertTrue(lim.check("k")[0])


class TestVersionVulnerable(unittest.TestCase):
    """Demuestra que los ataques SI funcionan contra la version sin controles."""

    def setUp(self):
        self.c = vuln.app.test_client()
        self.tok = self.c.post("/login", json={"usuario": "invitado", "password": "invitado"}).get_json()["token"]

    def test_40_sqli_union_extrae_usuarios(self):
        p = "x' UNION SELECT id,email,password_hash,1,1 FROM usuarios--"
        r = self.c.get("/api/productos", query_string={"categoria": p},
                       headers={"Authorization": "Bearer " + self.tok})
        self.assertIn("admin@act4.local", r.get_data(as_text=True))

    def test_41_alg_none_escala_a_admin(self):
        forged = b64({"alg": "none"}) + "." + b64({"sub": "atacante", "rol": "admin"}) + "."
        r = self.c.delete("/api/productos/1", headers={"Authorization": "Bearer " + forged})
        self.assertEqual(r.status_code, 200)

    def test_42_secreto_debil_permite_falsificar(self):
        forged = jwt.encode({"sub": "atacante", "rol": "admin"}, "secret", algorithm="HS256")
        r = self.c.delete("/api/productos/1", headers={"Authorization": "Bearer " + forged})
        self.assertEqual(r.status_code, 200)


if __name__ == "__main__":
    unittest.main(verbosity=2)
