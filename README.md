# Act4 Ciberseguridad — Santiago Gonzalez Ponce — AL03088820

Actividad 4: análisis de vulnerabilidades web, protección de API, diseño de red segura,
seguridad perimetral y evaluación integral de riesgos. Todo corre **localmente** en
contenedores Podman (rootless) o en las VM del laboratorio; nada se publica fuera de `127.0.0.1`.

| Carpeta | Paso | Contenido |
|---|---|---|
| [`lab-dvwa-zap/`](lab-dvwa-zap) | 1 | DVWA + MariaDB, plan de OWASP ZAP (sesión autenticada), confirmación manual de SQLi, XSS y control de acceso roto. |
| [`lab-api-segura/`](lab-api-segura) | 2 | API Flask con OAuth 2.0 (client credentials) + JWT RS256, validación de entradas, rate limiting 100/min, versión vulnerable para comparar, 25 pruebas y colección de Postman/Insomnia. |
| [`red-segura/`](red-segura) | 3 | Diagrama, direccionamiento y configuraciones IOS para Packet Tracer: 3 VLAN (+ gestión), ACL de mínimo privilegio y VPN IPsec. |
| [`perimetro-pfsense/`](perimetro-pfsense) | 4 | Diseño para pfSense: reglas por interfaz, VPN IPsec, filtrado de phishing con pfBlockerNG y configuración de Snort. |
| [`lab-perimetro/`](lab-perimetro) | 4 | Las mismas reglas implementadas y probadas en un firewall nftables con DNSBL y Snort en la WAN (23 pruebas + ataque nmap). |
| [`lab-snort/`](lab-snort) | 4 | Snort 2.9 con reglas personalizadas de escaneo, respuesta IPS (bloqueo del origen) y simulación con nmap. |
| [`docs/`](docs) | 5 | Reporte (.docx), matriz de riesgos 5x5, bitácora de IA y evidencias. |

## Requisitos

- Podman 5+ (o Docker) con Compose v2 · Python 3.12 · curl
- Packet Tracer 8.2 · VM de pfSense CE 2.7 (para las partes que no corren en contenedor)
- Postman o Insomnia (opcional)

## 1. DVWA + OWASP ZAP

```bash
cd lab-dvwa-zap
podman compose up -d                 # DVWA en http://127.0.0.1:4280 (admin / password)
./preparar-dvwa.sh                   # crea la BD, inicia sesión, nivel "low"
./escanear-zap.sh                    # spider + escaneo activo -> reportes/zap-dvwa.{html,json,md}
./confirmar-vulnerabilidades.sh      # SQLi, XSS reflejado y control de acceso roto con curl
```

## 2. API segura

```bash
cd lab-api-segura
python3 generate_secrets.py          # .env con secretos aleatorios (600)
podman build -t act4/api-segura:1.0 -f Containerfile .
podman run -d --name act4-api --env-file .env -p 127.0.0.1:5002:5002 --read-only \
  --mount type=tmpfs,dst=/app/data,chown=true --mount type=tmpfs,dst=/app/keys,chown=true \
  --cap-drop ALL --security-opt no-new-privileges act4/api-segura:1.0
python3 -m unittest discover -s tests -v   # necesita requirements.txt instalados
./probar.sh                          # OAuth -> JWT -> 401/403/400 -> 429
```
En Postman: *Import* → `postman/act4-api-segura.postman_collection.json`, pon
`client_secret` en las variables de la colección y usa el *Runner* con 101 iteraciones
en la petición 6 para ver el 429.

## 3. Red segura (Packet Tracer)

Ver [`red-segura/README.md`](red-segura/README.md): pasos de armado, configuraciones y 11 pruebas.

## 4. Perímetro: pfSense + Snort

```bash
cd lab-snort
podman build -t act4/snort:2.9 -f Containerfile.snort .
podman build -t act4/atacante:1.0 -f Containerfile.atacante .
./simular-ataque.sh                  # requiere DVWA arriba; IDS + bloqueo IPS
```
Firewall perimetral equivalente a pfSense (reglas, DNSBL y Snort en la WAN):

```bash
cd lab-perimetro && ./levantar.sh && ./validar.sh && ./ataque-snort.sh
```
Para pfSense real: [`perimetro-pfsense/README.md`](perimetro-pfsense/README.md).

## Seguridad

- Sin secretos, llaves ni cookies en Git (`.gitignore`); `.env.example` sin valores reales.
- `app_vulnerable.py` y DVWA son deliberadamente inseguros: solo escuchan en `127.0.0.1`.
- Las contraseñas de los archivos de Packet Tracer son de laboratorio; cámbialas en un equipo real.
