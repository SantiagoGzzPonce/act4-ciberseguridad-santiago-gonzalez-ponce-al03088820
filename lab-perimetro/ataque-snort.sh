#!/usr/bin/env bash
# Snort en la interfaz WAN del firewall (IPS con "Block Offenders") + ataque con nmap.
# Requiere ./levantar.sh. Las reglas son las mismas de lab-snort/rules (custom.rules).
set -uo pipefail
cd "$(dirname "$0")"
FW_WAN=198.51.100.2
WAN_IF=$(podman exec act4-fw ip -o -4 addr show | awk -v ip="$FW_WAN" '$4 ~ "^"ip"/" {print $2}')
mkdir -p logs; rm -f logs/*; chmod 777 logs
podman exec act4-fw nft flush set inet act4 bloqueados
podman rm -f -t 0 act4-snort-fw >/dev/null 2>&1
podman run -d --name act4-snort-fw --network container:act4-fw --cap-add NET_ADMIN,NET_RAW \
  -e MODO=nft -e PROTEGIDO=$FW_WAN \
  -v "$PWD/fw/snort-wan.conf":/etc/snort/act4/snort.conf:ro,Z -v "$PWD/../lab-snort/rules":/etc/snort/act4/rules:ro,Z \
  -v "$PWD/../lab-snort/ips-responder.sh":/usr/local/bin/ips-responder.sh:ro,Z -v "$PWD/logs":/var/log/snort:Z \
  act4/snort:2.9 bash -c "bash /usr/local/bin/ips-responder.sh & exec snort -q -i $WAN_IF -c /etc/snort/act4/snort.conf -l /var/log/snort" >/dev/null
sleep 6
A="podman exec act4-atacante"
echo "### Snort escuchando en la WAN del firewall ($WAN_IF, $FW_WAN) en modo IPS (Block Offenders)"
echo
echo "### ANTES: el atacante (198.51.100.66) visita el sitio publicado"
$A curl -s -m 4 -o /dev/null -w "curl http://$FW_WAN:443/ -> HTTP %{http_code}\n" "http://$FW_WAN:443/"
echo
echo "### ATAQUE: nmap -sS -T4 -p 1-1000 contra la WAN"
$A nmap -Pn -n -sS -T4 --max-retries 1 --host-timeout 40s -p 1-1000 "$FW_WAN" | grep -E "^PORT|open|filtered|Not shown|scanned|Skipping"
sleep 3
echo
echo "--- Services > Snort > Alerts (alert.fast, primeras 3)"
head -3 logs/alert.fast
echo "... $(wc -l < logs/alert.fast) alertas en total: threshold 'both' emite una por ventana de 5 s mientras el atacante sigue enviando SYN que ya se descartan"
echo
echo "--- sfPortscan"
grep -E "portscan|Scanner IP" logs/portscan.log | head -4
echo
echo "--- Services > Snort > Blocked (set nftables 'bloqueados' = tabla snort2c)"
podman exec act4-fw nft list set inet act4 bloqueados | grep -E "elements|expires" | sed 's/^\s*/  /'
cat logs/bloqueos.log
echo
echo "### DESPUÉS: el mismo atacante intenta de nuevo"
$A nmap -Pn -n -sS -p 443 "$FW_WAN" | grep -E "^PORT|443"
$A curl -s -m 4 -o /dev/null -w "curl http://$FW_WAN:443/ -> HTTP %{http_code} (000 = sin respuesta)\n" "http://$FW_WAN:443/"
echo
echo "### Otros usuarios no se ven afectados"
podman exec act4-inet-web curl -s -m 4 -o /dev/null -w "Cliente de Internet 198.51.100.80 -> sitio publicado: HTTP %{http_code}\n" "http://$FW_WAN:443/"
podman exec act4-pc-01 curl -s -m 4 -o /dev/null -w "PC-01 (INTERNA) -> SRV-WEB: HTTP %{http_code}\n" "http://172.16.10.10:443/"
echo
echo "--- Contador de la regla de bloqueo"
podman exec act4-fw nft list chain inet act4 forward | grep "SNORT" | sed 's/^\s*/  /'
