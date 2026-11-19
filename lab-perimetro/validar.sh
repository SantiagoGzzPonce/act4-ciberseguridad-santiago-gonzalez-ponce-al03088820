#!/usr/bin/env bash
# Valida las reglas del perimetro: cada prueba dice que se espera (PERMITIDO /
# BLOQUEADO) y compara con lo que realmente ocurre. Equivale a probar desde cada
# VLAN contra pfSense y revisar Status > System Logs > Firewall.
cd "$(dirname "$0")"
OK=0; FAIL=0
tcp() {  # tcp ORIGEN DESTINO PUERTO ESPERADO REGLA DESCRIPCION
  if podman exec "act4-$1" nc -z -w 2 "$2" "$3" 2>/dev/null; then r=PERMITIDO; else r=BLOQUEADO; fi
  [[ $r == "$4" ]] && { m="✔"; OK=$((OK+1)); } || { m="✘"; FAIL=$((FAIL+1)); }
  printf ' %s %-13s → %-15s %-5s %-10s %-11s %s\n' "$m" "$1" "$2" "$3" "$r" "$5" "$6"
}
dns() {  # dns ORIGEN SERVIDOR DOMINIO ESPERADO REGLA DESCRIPCION
  r=$(podman exec "act4-$1" dig +short +time=2 +tries=1 "@$2" "$3" 2>/dev/null | tail -1)
  [[ -z "$r" || "$r" == ";;"* ]] && r="(sin respuesta)"
  [[ "$r" == "$4" ]] && { m="✔"; OK=$((OK+1)); } || { m="✘"; FAIL=$((FAIL+1)); }
  printf ' %s %-13s %-34s @%-14s → %-16s %-11s %s\n' "$m" "$1" "$3" "$2" "$r" "$5" "$6"
}
echo "=== 1. Segmentación (Firewall > Rules por interfaz)"
printf '   %-13s   %-15s %-5s %-10s %-11s %s\n' ORIGEN DESTINO PUERTO RESULTADO REGLA DESCRIPCION
tcp pc-01        172.16.10.10 443  PERMITIDO INTERNA-5 "Usuario usa el web publicado en la DMZ"
tcp pc-01        198.51.100.80 443 PERMITIDO INTERNA-8 "Usuario navega en Internet"
tcp pc-01        172.16.30.21 443  BLOQUEADO INTERNA-7 "Usuario no llega a la cámara IoT"
tcp pc-admin     172.16.30.21 443  PERMITIDO INTERNA-6 "Solo PC-ADMIN administra IoT"
tcp pc-01        172.16.20.1  443  BLOQUEADO INTERNA-2 "Usuario no llega al WebGUI del firewall"
tcp pc-admin     172.16.20.1  443  PERMITIDO INTERNA-1 "PC-ADMIN sí llega al WebGUI"
tcp srv-web      172.16.20.10 445  BLOQUEADO DMZ-2     "DMZ comprometida no llega a INTERNA"
tcp srv-web      172.16.30.21 443  BLOQUEADO DMZ-3     "DMZ no llega a IoT"
tcp srv-web      198.51.100.80 80  PERMITIDO DMZ-4     "Servidor DMZ descarga actualizaciones"
tcp cam-01       172.16.10.20 8883 PERMITIDO IOT-2     "Cámara habla con su broker MQTT/TLS"
tcp cam-01       172.16.20.10 445  BLOQUEADO IOT-3     "IoT no llega a la red interna"
tcp cam-01       172.16.20.50 443  BLOQUEADO IOT-3     "IoT no llega a PC-ADMIN"
tcp cam-01       198.51.100.80 443 BLOQUEADO IOT-4     "IoT sin Internet directo"
tcp atacante     198.51.100.2 443  PERMITIDO WAN-1     "Internet llega al web publicado (NAT 443)"
tcp atacante     198.51.100.2 22   BLOQUEADO WAN-deny  "SSH del firewall no expuesto"
tcp atacante     172.16.20.10 445  BLOQUEADO WAN-deny  "Internet no alcanza la red interna"
tcp atacante     172.16.10.10 80   BLOQUEADO WAN-deny  "Solo 443 está publicado"
echo
echo "=== 2. Filtrado de contenido: DNSBL de phishing (pfBlockerNG)"
dns pc-01  172.16.20.1   login-banco-seguro-mx.com          10.10.10.1     DNSBL     "Dominio de phishing → VIP de bloqueo"
dns pc-01  172.16.20.1   cuenta.verificacion-cuenta-paypal.net 10.10.10.1  DNSBL     "Subdominio también bloqueado"
dns cam-01 172.16.30.1   microsoft365-soporte-login.com     10.10.10.1     DNSBL     "También protege la VLAN IoT"
dns pc-01  172.16.20.1   www.act4.local                     172.16.10.10   Resolver  "Dominio interno resuelve normal"
dns pc-01  172.16.20.1   www.unam.mx                        198.51.100.80  Resolver  "Dominio legítimo resuelve normal"
dns pc-01  198.51.100.53 login-banco-seguro-mx.com          "(sin respuesta)" INTERNA-4 "No se puede esquivar con DNS externo"
echo
echo "Resultado: $OK correctas, $FAIL fallidas"
echo
echo "=== 3. Contadores por regla (equivale a States / Firewall logs de pfSense)"
podman exec act4-fw nft list table inet act4 | grep -E 'counter packets [1-9]' | grep -oE 'counter packets [0-9]+ bytes [0-9]+.*comment "[^"]+"' \
  | sed -E 's/counter packets ([0-9]+) bytes [0-9]+.*comment "([^"]+)"/  \1 paquetes\t\2/' | grep -v 'Port forward\|Outbound NAT' | sort -t$'\t' -k2
echo
echo "=== 4. Consultas registradas por el resolver (Reports > Alerts > DNSBL)"
podman exec act4-fw grep -E "config .* is 10\.10\.10\.1" /var/log/dnsmasq.log | sed -E "s/^.*dnsmasq\\[[0-9]+\\]: [0-9]+ //" | sort -u
exit $FAIL
