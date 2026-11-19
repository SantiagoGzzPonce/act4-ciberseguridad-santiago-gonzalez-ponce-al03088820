#!/usr/bin/env bash
# Prueba de punta a punta contra la API en ejecucion (python app.py o contenedor).
# Uso: ./probar.sh [http://127.0.0.1:5002]   (lee los secretos de .env)
set -euo pipefail
API=${1:-http://127.0.0.1:5002}
set -a; source "$(dirname "$0")/.env"; set +a
j() { python3 -c 'import sys,json; print(json.dumps(json.load(sys.stdin), ensure_ascii=False))'; }
code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }

echo "== 1. OAuth 2.0 client_credentials -> JWT"
TOKEN=$(curl -s -u "app-lectura:$CLIENT_LECTURA_SECRET" -d grant_type=client_credentials "$API/oauth/token" \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')
echo "header : $(echo "$TOKEN" | cut -d. -f1 | base64 -d 2>/dev/null || true)"
echo "payload: $(echo "$TOKEN" | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null || true)"
echo "secreto incorrecto -> $(code -u app-lectura:mal -d grant_type=client_credentials "$API/oauth/token")"

echo "== 2. Acceso al recurso"
echo "sin token            -> $(code "$API/api/productos")"
echo "con token            -> $(code -H "Authorization: Bearer $TOKEN" "$API/api/productos")"
NONE="$(printf '{"alg":"none"}' | base64 | tr -d '=')"."$(echo "$TOKEN" | cut -d. -f2)".
echo "token alg=none       -> $(code -H "Authorization: Bearer $NONE" "$API/api/productos")"
echo "POST sin scope write -> $(code -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{"nombre":"X1","categoria":"iot","precio":1,"stock":1}' "$API/api/productos")"

echo "== 3. Validacion de entradas (inyeccion)"
for p in "redes' OR '1'='1" "x' UNION SELECT id,email,password_hash,1,1 FROM usuarios--" "redes"; do
  printf '%-60s -> %s\n' "categoria=$p" "$(code -G -H "Authorization: Bearer $TOKEN" --data-urlencode "categoria=$p" "$API/api/productos")"
done
curl -s -G -H "Authorization: Bearer $TOKEN" --data-urlencode "categoria=redes' OR '1'='1" "$API/api/productos" | j

echo "== 4. Rate limiting (120 solicitudes seguidas)"
for i in $(seq 1 120); do code -H "Authorization: Bearer $TOKEN" "$API/api/productos/1"; echo; done | sort | uniq -c
curl -s -D - -o /dev/null -H "Authorization: Bearer $TOKEN" "$API/api/productos/1" | grep -iE '^HTTP|retry-after|x-ratelimit'
