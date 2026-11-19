#!/usr/bin/env bash
# Ejecuta OWASP ZAP (contenedor oficial) contra DVWA dentro de la red act4-lab.
set -euo pipefail
cd "$(dirname "$0")"
[ -f .cookie ] || ./preparar-dvwa.sh
sed "s|__COOKIE__|$(cat .cookie)|" zap-plan.yaml.tpl > reportes/.zap-plan.yaml
chmod 777 reportes
podman run --rm --network act4-lab -v "$PWD":/zap/wrk:Z ghcr.io/zaproxy/zaproxy:stable \
  zap.sh -cmd -autorun /zap/wrk/reportes/.zap-plan.yaml
rm -f reportes/.zap-plan.yaml
