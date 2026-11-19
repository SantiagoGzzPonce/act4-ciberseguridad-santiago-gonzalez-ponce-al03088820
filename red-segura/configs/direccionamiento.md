# Tabla de direccionamiento

| VLAN | Nombre | Red | Gateway (R-EDGE) | Equipos |
|---|---|---|---|---|
| 10 | DMZ | 172.16.10.0/24 | 172.16.10.1 | SRV-WEB .10 (publicado en 200.10.10.2:443), SRV-DNS .11, BROKER-IOT .20 |
| 20 | INTERNA | 172.16.20.0/24 | 172.16.20.1 | SRV-ARCHIVOS .10, PC-ADMIN .50, PC-01/PC-02 por DHCP (.21+) |
| 30 | IOT | 172.16.30.0/24 | 172.16.30.1 | CAM-01, SENSOR-01, TERMOSTATO-01 por DHCP (.21+) |
| 99 | GESTION (nativa) | 172.16.99.0/24 | 172.16.99.1 | SW-CORE .2 |
| 999 | NO-USADOS | — | — | puertos apagados |
| — | WAN | 200.10.10.0/30 | 200.10.10.1 (R-ISP) | R-EDGE G0/0 .2 |
| — | Internet simulada | 198.51.100.0/24 | 198.51.100.1 | PC-REMOTO .10 |
| — | Pool VPN | 10.10.50.0/24 | — | clientes VPN .10–.100 |

## Puertos de SW-CORE

| Puerto | VLAN | Uso |
|---|---|---|
| Gi0/1 | troncal 10,20,30,99 (nativa 99) | R-EDGE Gi0/1 |
| Fa0/1–4 | 10 DMZ | SRV-WEB Fa0/1, SRV-DNS Fa0/2, BROKER-IOT Fa0/3 |
| Fa0/5–12 | 20 INTERNA | SRV-ARCHIVOS Fa0/5, PC-ADMIN Fa0/6, PC-01 Fa0/7, PC-02 Fa0/8 |
| Fa0/13–18 | 30 IOT | CAM-01 Fa0/13, SENSOR-01 Fa0/14, TERMOSTATO-01 Fa0/15 |
| Fa0/19–24, Gi0/2 | 999 | apagados |
