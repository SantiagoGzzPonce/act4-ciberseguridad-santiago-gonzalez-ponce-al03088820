#!/usr/bin/env bash
# Levanta el perimetro equivalente a pfSense: 4 redes (WAN, DMZ, INTERNA, IOT),
# el firewall y los equipos de cada zona, con el direccionamiento del diseño.
set -euo pipefail
cd "$(dirname "$0")"
for n in "wan 198.51.100" "dmz 172.16.10" "interna 172.16.20" "iot 172.16.30"; do
  set -- $n
  podman network exists act4-$1 || podman network create --internal --subnet $2.0/24 --gateway $2.254 act4-$1 >/dev/null
done
./bajar.sh >/dev/null 2>&1 || true

podman run -d --name act4-fw --hostname fw-act4 --cap-add NET_ADMIN,NET_RAW \
  --sysctl net.ipv4.ip_forward=1 \
  --network act4-wan:ip=198.51.100.2 --network act4-dmz:ip=172.16.10.1 \
  --network act4-interna:ip=172.16.20.1 --network act4-iot:ip=172.16.30.1 \
  -v "$PWD/fw/reglas.nft.tpl":/act4/reglas.nft.tpl:ro,Z -v "$PWD/fw/dnsmasq.conf":/act4/dnsmasq.conf:ro,Z \
  -v "$PWD/fw/entrypoint.sh":/act4/entrypoint.sh:ro,Z \
  -v "$PWD/../perimetro-pfsense/phishing-dominios.txt":/act4/phishing-dominios.txt:ro,Z \
  act4/fw:1.0 bash /act4/entrypoint.sh >/dev/null

# equipo NOMBRE RED IP GATEWAY "SERVICIO"
equipo() {
  podman run -d --name "act4-$1" --hostname "$1" --cap-add NET_ADMIN,NET_RAW --network "act4-$2:ip=$3" act4/cliente:1.0 \
    bash -c "ip route replace default via $4; echo 'nameserver $4' > /etc/resolv.conf; $5 exec sleep infinity" >/dev/null
}
web() { echo "cd /tmp && echo $1 > index.html && for p in $2; do python3 -m http.server \$p >/dev/null 2>&1 & done;"; }
# DMZ
equipo srv-web     dmz     172.16.10.10 172.16.10.1 "$(web SRV-WEB '80 443')"
equipo broker-iot  dmz     172.16.10.20 172.16.10.1 "$(web BROKER '8883')"
# INTERNA
equipo srv-archivos interna 172.16.20.10 172.16.20.1 "$(web ARCHIVOS '445')"
equipo pc-admin    interna 172.16.20.50 172.16.20.1 ""
equipo pc-01       interna 172.16.20.21 172.16.20.1 ""
# IOT
equipo cam-01      iot     172.16.30.21 172.16.30.1 "$(web CAMARA '443')"
# "Internet": un sitio web, un DNS publico y el atacante
equipo inet-web    wan     198.51.100.80 198.51.100.2 "$(web SITIO-EXTERNO '80 443')"
equipo inet-dns    wan     198.51.100.53 198.51.100.2 "dnsmasq --no-resolv --no-hosts --address=/#/198.51.100.80 --log-queries;"
equipo atacante    wan     198.51.100.66 198.51.100.2 "ip route add 172.16.0.0/16 via 198.51.100.2;"
sleep 3
podman logs act4-fw
podman ps --filter name=act4- --format '{{.Names}}' | grep -vE 'api|dvwa' | sort | tr '\n' ' '; echo
