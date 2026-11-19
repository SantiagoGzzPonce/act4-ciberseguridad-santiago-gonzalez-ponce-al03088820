#!/usr/bin/env bash
# Detiene y elimina los contenedores del perimetro (las redes se conservan).
# snort-fw primero: comparte la red del firewall y bloquea su borrado
for c in snort-fw fw srv-web broker-iot srv-archivos pc-admin pc-01 cam-01 inet-web inet-dns atacante; do
  podman rm -f -t 0 "act4-$c" >/dev/null 2>&1
done
echo "Perimetro detenido"
