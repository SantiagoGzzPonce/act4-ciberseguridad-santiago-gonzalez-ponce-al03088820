#!/usr/sbin/nft -f
# =============================================================================
# Reglas del firewall perimetral Act4 = traduccion 1:1 de las reglas de pfSense
# (perimetro-pfsense/README.md). Igual que pfSense: se filtra por interfaz de
# ENTRADA, primera coincidencia gana, estado (ct) para respuestas y deny final.
# Cada regla lleva contador (equivale a la columna "States" de pfSense) y el
# comentario con su numero en las tablas del reporte.
# Las interfaces @WAN@ @DMZ@ @INTERNA@ @IOT@ las sustituye entrypoint.sh.
# =============================================================================
flush ruleset

define WAN      = "@WAN@"
define DMZ      = "@DMZ@"
define INTERNA  = "@INTERNA@"
define IOT      = "@IOT@"
define DMZ_NET      = 172.16.10.0/24
define INTERNA_NET  = 172.16.20.0/24
define IOT_NET      = 172.16.30.0/24
define SRV_WEB      = 172.16.10.10
define BROKER_IOT   = 172.16.10.20
define PC_ADMIN     = 172.16.20.50

table inet act4 {
  # Equivale a la tabla "snort2c" de pfSense: Snort agrega aqui a los atacantes
  set bloqueados {
    type ipv4_addr; flags timeout; timeout 1h
    comment "Snort Block Offenders (snort2c)"
  }
  set rfc1918 {
    type ipv4_addr; flags interval
    elements = { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 }
  }

  # ---------------- Trafico dirigido al propio firewall ----------------
  chain input {
    type filter hook input priority filter; policy drop;
    ip saddr @bloqueados counter drop comment "SNORT bloqueado"
    ct state established,related accept
    ct state invalid drop
    iif lo accept
    iifname $INTERNA ip saddr $PC_ADMIN tcp dport { 22, 443 } counter accept comment "INTERNA-1 PC_ADMIN -> WebGUI/SSH"
    iifname $INTERNA tcp dport { 22, 443 } counter drop comment "INTERNA-2 nadie mas administra el firewall"
    iifname { $INTERNA, $IOT, $DMZ } udp dport 53 counter accept comment "INTERNA-3 / IOT-1 / DMZ-1 DNS Resolver"
    iifname $IOT udp dport 67 counter accept comment "IOT-1 DHCP"
    counter drop comment "Deny implicito (input)"
  }

  # ---------------- Trafico que atraviesa el firewall ----------------
  chain forward {
    type filter hook forward priority filter; policy drop;
    ip saddr @bloqueados counter drop comment "SNORT bloqueado"
    ct state established,related accept
    ct state invalid drop

    # WAN
    iifname $WAN ct status dnat ip daddr $SRV_WEB tcp dport 443 counter accept comment "WAN-1 NAT HTTPS -> SRV_WEB"

    # INTERNA
    iifname $INTERNA meta l4proto { tcp, udp } th dport { 53, 853 } counter drop comment "INTERNA-4 bloquea DNS/DoT externo"
    iifname $INTERNA ip daddr $SRV_WEB tcp dport 443 counter accept comment "INTERNA-5 web publicado en DMZ"
    iifname $INTERNA ip saddr $PC_ADMIN ip daddr { $DMZ_NET, $IOT_NET } tcp dport { 22, 443 } counter accept comment "INTERNA-6 administracion"
    iifname $INTERNA ip daddr @rfc1918 counter drop comment "INTERNA-7 resto de redes privadas"
    iifname $INTERNA oifname $WAN tcp dport { 80, 443 } counter accept comment "INTERNA-8 navegacion"

    # DMZ
    iifname $DMZ ip daddr $INTERNA_NET counter drop comment "DMZ-2 DMZ no llega a INTERNA"
    iifname $DMZ ip daddr $IOT_NET counter drop comment "DMZ-3 sin movimiento lateral a IoT"
    iifname $DMZ oifname $WAN tcp dport { 80, 443 } counter accept comment "DMZ-4 actualizaciones"

    # IOT
    iifname $IOT ip daddr $BROKER_IOT tcp dport 8883 counter accept comment "IOT-2 MQTT/TLS al broker"
    iifname $IOT ip daddr $INTERNA_NET counter drop comment "IOT-3 IoT no llega a INTERNA"
    iifname $IOT counter drop comment "IOT-4 sin Internet directo"

    counter drop comment "Deny implicito (forward)"
  }

  # ---------------- NAT ----------------
  chain prerouting {
    type nat hook prerouting priority dstnat;
    iifname $WAN tcp dport 443 counter dnat ip to $SRV_WEB comment "Port forward 443 -> SRV_WEB"
  }
  chain postrouting {
    type nat hook postrouting priority srcnat;
    oifname $WAN counter masquerade comment "Outbound NAT"
  }
}
