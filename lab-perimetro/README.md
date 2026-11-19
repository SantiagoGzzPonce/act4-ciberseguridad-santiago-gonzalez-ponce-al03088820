# Perímetro equivalente a pfSense en contenedores (Paso 4)

pfSense corre sobre FreeBSD y no se puede contener. Este laboratorio implementa **las mismas
reglas** de [`../perimetro-pfsense`](../perimetro-pfsense) en un firewall Linux para probarlas
con tráfico real:

| pfSense | Aquí |
|---|---|
| Firewall > Rules (pf), por interfaz | [`fw/reglas.nft.tpl`](fw/reglas.nft.tpl) — nftables, misma numeración (INTERNA-1 … IOT-4) |
| NAT Port Forward / Outbound | `dnat` 443 → SRV-WEB, `masquerade` hacia WAN |
| States / System Logs > Firewall | contador por regla (`nft list table inet act4`) |
| DNS Resolver + pfBlockerNG DNSBL | dnsmasq: dominios de [`phishing-dominios.txt`](../perimetro-pfsense/phishing-dominios.txt) → VIP 10.10.10.1 |
| Snort + Block Offenders (`snort2c`) | Snort 2.9 en la WAN + set `bloqueados` de nftables |

Redes (todas `--internal`, sin salida real): WAN 198.51.100.0/24, DMZ 172.16.10.0/24,
INTERNA 172.16.20.0/24, IOT 172.16.30.0/24. El firewall es .1 en cada zona y .2 en la WAN.

```bash
podman build -t act4/fw:1.0 -f Containerfile.fw .
podman build -t act4/cliente:1.0 -f Containerfile.cliente .
podman build -t act4/snort:2.9 -f ../lab-snort/Containerfile.snort ../lab-snort
./levantar.sh        # firewall + SRV-WEB, BROKER, SRV-ARCHIVOS, PC-ADMIN, PC-01, CAM-01, "Internet", atacante
./validar.sh         # 17 pruebas de segmentación + 6 de DNSBL, con contadores por regla
./ataque-snort.sh    # nmap desde la WAN -> alerta -> IP en el set "bloqueados" -> sin acceso
./bajar.sh
```

Evidencias: `docs/evidencias/perimetro-validacion.txt`, `perimetro-snort.txt` y
`perimetro-reglas-nft.txt` (reglas cargadas con sus contadores).
