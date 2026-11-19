#!/usr/bin/env bash
# Crea la BD de DVWA, inicia sesion (admin/password, credenciales de laboratorio de DVWA),
# fija el nivel de seguridad "low" y guarda la cookie en .cookie para ZAP y curl.
set -euo pipefail
URL=${1:-http://127.0.0.1:4280}
JAR=$(mktemp); trap 'rm -f "$JAR"' EXIT
tok() { grep -oP "user_token' value='\K[0-9a-f]+" ; }
T=$(curl -s -c "$JAR" -b "$JAR" "$URL/setup.php" | tok)
curl -s -c "$JAR" -b "$JAR" -d "create_db=Create+%2F+Reset+Database&user_token=$T" "$URL/setup.php" >/dev/null
sleep 2
T=$(curl -s -c "$JAR" -b "$JAR" "$URL/login.php" | tok)
curl -s -c "$JAR" -b "$JAR" -d "username=admin&password=password&Login=Login&user_token=$T" "$URL/login.php" -o /dev/null
T=$(curl -s -c "$JAR" -b "$JAR" "$URL/security.php" | tok)
curl -s -c "$JAR" -b "$JAR" -d "security=low&seclev_submit=Submit&user_token=$T" "$URL/security.php" -o /dev/null
SID=$(awk '$6=="PHPSESSID"{print $7}' "$JAR" | tail -1)
echo "PHPSESSID=$SID; security=low" > .cookie
curl -s -b "$(cat .cookie)" "$URL/index.php" | grep -q "Logout" && echo "Sesion lista (security=low)" || { echo "Fallo el login"; exit 1; }
