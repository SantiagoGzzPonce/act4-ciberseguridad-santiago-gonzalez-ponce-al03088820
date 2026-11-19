#!/usr/bin/env bash
# Respuesta IPS: emula "Block Offenders" de Snort en pfSense. Lee alert.fast y, ante
# una alerta ACT4 SCAN, inserta un DROP para la IP de origen en la interfaz protegida.
# Corre dentro del contenedor de Snort, que comparte el namespace de red del servidor.
LOG=/var/log/snort/alert.fast
WHITELIST="10.89.0.1 ${PROTEGIDO:-}"   # gateway y el propio servidor (pass list de pfSense)
touch "$LOG"
tail -n0 -F "$LOG" | while read -r line; do
  [[ "$line" == *"ACT4 SCAN"* ]] || continue
  src=$(grep -oP '\} \K[0-9.]+(?=(:[0-9]+)? ->)' <<<"$line")
  dst=$(grep -oP -- '-> \K[0-9.]+' <<<"$line")
  # La regla 1000002 ve la respuesta del servidor (RST): el atacante es el destino
  [[ "$src" == "${PROTEGIDO:-}" ]] && src=$dst
  [[ -z "$src" || " $WHITELIST " == *" $src "* ]] && continue
  if ! iptables -C INPUT -s "$src" -j DROP 2>/dev/null; then
    iptables -I INPUT -s "$src" -j DROP
    echo "$(date -Is) BLOQUEADO $src  <- $line" | tee -a /var/log/snort/bloqueos.log
  fi
done
