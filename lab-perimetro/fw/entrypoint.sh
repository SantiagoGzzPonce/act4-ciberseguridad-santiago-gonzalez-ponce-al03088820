#!/usr/bin/env bash
# Arranque del firewall: detecta las interfaces por su IP, carga las reglas,
# genera la DNSBL de phishing y levanta el DNS y el "WebGUI".
set -euo pipefail
ifc() { ip -o -4 addr show | awk -v ip="$1" '$4 ~ "^"ip"/" {print $2}'; }
WAN=$(ifc 198.51.100.2); DMZ=$(ifc 172.16.10.1); INTERNA=$(ifc 172.16.20.1); IOT=$(ifc 172.16.30.1)
echo "Interfaces: WAN=$WAN DMZ=$DMZ INTERNA=$INTERNA IOT=$IOT"
sed -e "s/@WAN@/$WAN/; s/@DMZ@/$DMZ/; s/@INTERNA@/$INTERNA/; s/@IOT@/$IOT/" /act4/reglas.nft.tpl > /etc/act4-reglas.nft
nft -f /etc/act4-reglas.nft
# DNSBL: cada dominio de la lista (y sus subdominios) responde la VIP 10.10.10.1
mkdir -p /etc/dnsmasq.d
grep -vE '^\s*(#|$)' /act4/phishing-dominios.txt | sed 's#.*#address=/&/10.10.10.1#' > /etc/dnsmasq.d/dnsbl-phishing.conf
echo "DNSBL: $(wc -l < /etc/dnsmasq.d/dnsbl-phishing.conf) dominios de phishing"
dnsmasq -C /act4/dnsmasq.conf
# "WebGUI" del firewall en 443 (para probar INTERNA-1/2)
cd /tmp && echo "pfSense WebGUI (simulado)" > index.html && python3 -m http.server 443 >/dev/null 2>&1 &
echo "Firewall listo"
exec sleep infinity
