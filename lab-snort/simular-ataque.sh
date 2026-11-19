#!/usr/bin/env bash
# Simula el ataque con nmap contra el servidor DMZ (DVWA) y valida IDS + respuesta IPS.
# Requisitos: lab-dvwa-zap levantado (podman compose up -d) e imagenes construidas.
set -uo pipefail
cd "$(dirname "$0")"
TARGET_CT=act4-dvwa-dvwa-1
TARGET_IP=$(podman inspect $TARGET_CT --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
rm -f logs/*; chmod 777 logs
podman rm -f act4-snort >/dev/null 2>&1
echo "### Sensor Snort en la interfaz de $TARGET_CT ($TARGET_IP)"
podman run -d --name act4-snort --network container:$TARGET_CT --cap-add NET_RAW,NET_ADMIN \
  -v "$PWD/snort.conf":/etc/snort/act4/snort.conf:ro,Z -v "$PWD/rules":/etc/snort/act4/rules:ro,Z \
  -v "$PWD/ips-responder.sh":/usr/local/bin/ips-responder.sh:ro,Z -v "$PWD/logs":/var/log/snort:Z \
  -e PROTEGIDO="$TARGET_IP" act4/snort:2.9 \
  bash -c 'iptables -F INPUT; bash /usr/local/bin/ips-responder.sh & exec snort -q -i eth0 -c /etc/snort/act4/snort.conf -l /var/log/snort' >/dev/null
sleep 6
# Atacante persistente (misma IP en las fases 1 y 2)
podman rm -f -t 0 act4-atacante >/dev/null 2>&1
podman run -d --name act4-atacante --network act4-lab --cap-add NET_RAW,NET_ADMIN act4/atacante:1.0 sleep infinity >/dev/null
ATK_IP=$(podman inspect act4-atacante --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
ATK="podman exec act4-atacante"
NUEVO="podman run --rm --network act4-lab --cap-add NET_RAW,NET_ADMIN act4/atacante:1.0"
echo "### Atacante: act4-atacante ($ATK_IP)"

echo; echo "### FASE 1 - IDS: reconocimiento del atacante (antes del bloqueo)"
echo "--- nmap -sS -T4 -p 1-1000 (SYN scan)"
$ATK nmap -Pn -n -sS -T4 -p 1-1000 "$TARGET_IP" | grep -E "^PORT|open|closed|filtered|scanned"
sleep 4
echo; echo "--- alert.fast"
cat logs/alert.fast
echo; echo "--- bloqueos aplicados por el responder IPS"
cat logs/bloqueos.log 2>/dev/null
echo; echo "--- reglas iptables en el servidor"
podman exec act4-snort iptables -S INPUT

echo; echo "### FASE 2 - IPS: el mismo atacante ($ATK_IP) intenta de nuevo"
$ATK nmap -Pn -n -sS -T4 -p 22,80,443 "$TARGET_IP" | grep -E "^PORT|open|closed|filtered|scanned"
$ATK curl -s -m 5 -o /dev/null -w "curl http://$TARGET_IP/ -> HTTP %{http_code} (000 = sin respuesta)\n" "http://$TARGET_IP/login.php"

echo; echo "### FASE 3 - Otras tecnicas desde atacantes nuevos (IP distinta en cada contenedor)"
for t in "-sN" "-sF" "-sX"; do
  $NUEVO nmap -Pn -n $t -T4 -p 1-200 "$TARGET_IP" >/dev/null 2>&1
done
$NUEVO nmap -Pn -n -sT -p 80 --script http-title "$TARGET_IP" >/dev/null 2>&1
sleep 4
echo "--- alert.fast (completo)"
cat logs/alert.fast
echo; echo "--- resumen por regla"
grep -oP '\[1:\K[0-9]+(?=:)|\[122:\K[0-9]+' logs/alert.fast | sort | uniq -c
echo; echo "--- sfPortscan (portscan.log, primeras lineas)"
head -12 logs/portscan.log 2>/dev/null
echo; echo "--- bloqueos.log"
cat logs/bloqueos.log
echo; echo "--- Control: un cliente legitimo nuevo (sin escanear) sigue entrando"
$NUEVO curl -s -m 5 -o /dev/null -w "curl http://$TARGET_IP/login.php -> HTTP %{http_code}\n" "http://$TARGET_IP/login.php"
podman rm -f -t 0 act4-atacante >/dev/null
