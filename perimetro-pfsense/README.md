# Seguridad perimetral con pfSense + Snort (Paso 4)

Entorno virtualizado (VirtualBox/VMware/Proxmox). Usa el mismo direccionamiento que el
diseño de Packet Tracer ([`../red-segura`](../red-segura)); aquí pfSense toma el papel de
gateway/firewall de las tres VLAN.

| VM | Adaptador | Red | IP |
|---|---|---|---|
| pfSense CE 2.7.2 | em0 (NAT/bridge) | WAN | DHCP |
| | em1 (red interna `act4-trunk`, modo promiscuo "permitir todo") | troncal 802.1Q | — |
| | em1.10 | DMZ | 172.16.10.1/24 |
| | em1.20 | INTERNA | 172.16.20.1/24 |
| | em1.30 | IOT | 172.16.30.1/24 |
| Ubuntu + DVWA (contenedor) | VLAN 10 | DMZ | 172.16.10.10 |
| Kali / Ubuntu + nmap (atacante) | WAN o VLAN 30 | — | — |
| PC interna de prueba | VLAN 20 | INTERNA | DHCP |

> Si el hipervisor no maneja bien 802.1Q en la red interna, crea tres redes internas
> (`act4-dmz`, `act4-interna`, `act4-iot`) y asígnalas a em1/em2/em3: las reglas son las mismas.

## 1. Interfaces y VLAN

1. *Interfaces > Assignments > VLANs > Add*: padre `em1`, tags 10, 20 y 30.
2. *Interfaces > Assignments*: agrega `em1.10`, `em1.20`, `em1.30` y renómbralas `DMZ`,
   `INTERNA`, `IOT`. Habilítalas con IPv4 estática (tabla de arriba).
3. *Services > DHCP Server*: activa DHCP en INTERNA (.100–.200) e IOT (.100–.200), DNS = la
   IP de la interfaz (DNS Resolver de pfSense, necesario para el filtrado de contenido).
4. *Interfaces > WAN*: deja marcadas **Block private networks** y **Block bogon networks**.

## 2. Alias (Firewall > Aliases)

| Alias | Tipo | Contenido |
|---|---|---|
| `RFC1918` | Network | 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 |
| `SRV_WEB` | Host | 172.16.10.10 |
| `BROKER_IOT` | Host | 172.16.10.20 |
| `PC_ADMIN` | Host | 172.16.20.50 |
| `PUERTOS_WEB` | Port | 80, 443 |
| `PUERTOS_ADMIN_FW` | Port | 22, 443 (WebGUI) |

Las redes también se pueden importar con *Aliases > Import* usando [`alias-redes.txt`](alias-redes.txt).

## 3. Reglas de firewall (Firewall > Rules)

pfSense evalúa **por interfaz de entrada**, de arriba hacia abajo, y la primera
coincidencia gana; al final de cada interfaz hay un *deny* implícito. Todas las reglas de
bloqueo llevan **Log** activado para tener evidencia.

### WAN
| # | Acción | Proto | Origen | Destino | Puerto | Descripción |
|---|---|---|---|---|---|---|
| 1 | Pass | TCP | any | `SRV_WEB` | 443 | NAT port forward HTTPS → DMZ (regla creada por *Firewall > NAT > Port Forward*) |
| 2 | Pass | UDP | any | WAN address | 500, 4500 | IKE/NAT-T para la VPN IPsec |
| 3 | Pass | ESP | any | WAN address | — | IPsec |
| — | (implícito) Block | any | any | any | — | Todo lo demás, incluido el WebGUI desde Internet |

### INTERNA (`em1.20`)
| # | Acción | Proto | Origen | Destino | Puerto | Descripción |
|---|---|---|---|---|---|---|
| 1 | Pass | TCP | `PC_ADMIN` | This Firewall | `PUERTOS_ADMIN_FW` | Solo PC-ADMIN administra el firewall (*anti-lockout* desactivado en *System > Advanced*) |
| 2 | Block | any | INTERNA net | This Firewall | `PUERTOS_ADMIN_FW` | Nadie más llega al WebGUI/SSH |
| 3 | Pass | TCP/UDP | INTERNA net | INTERNA address | 53 | DNS Resolver (filtrado de phishing) |
| 4 | Block | TCP/UDP | INTERNA net | any | 53, 853 | Impide saltarse el filtro con DNS externo / DoT |
| 5 | Pass | TCP | INTERNA net | `SRV_WEB` | 443 | Servicio publicado en la DMZ |
| 6 | Pass | TCP | `PC_ADMIN` | DMZ net, IOT net | 22, 443 | Administración |
| 7 | Block | any | INTERNA net | `RFC1918` | any | Resto de redes privadas (DMZ, IoT, gestión) |
| 8 | Pass | TCP | INTERNA net | !`RFC1918` | `PUERTOS_WEB` | Navegación |

### DMZ (`em1.10`)
| # | Acción | Proto | Origen | Destino | Puerto | Descripción |
|---|---|---|---|---|---|---|
| 1 | Pass | UDP | DMZ net | DMZ address | 53 | DNS |
| 2 | **Block** | any | DMZ net | **INTERNA net** | any | **Un servidor DMZ comprometido no llega a la red interna** |
| 3 | Block | any | DMZ net | IOT net, This Firewall | any | Sin movimiento lateral ni acceso al firewall |
| 4 | Pass | TCP | DMZ net | !`RFC1918` | `PUERTOS_WEB` | Actualizaciones |

### IOT (`em1.30`)
| # | Acción | Proto | Origen | Destino | Puerto | Descripción |
|---|---|---|---|---|---|---|
| 1 | Pass | UDP | IOT net | IOT address | 53, 67 | DNS y DHCP |
| 2 | Pass | TCP | IOT net | `BROKER_IOT` | 8883 | MQTT sobre TLS |
| 3 | **Block** | any | IOT net | **INTERNA net** | any | **Bloqueo de tráfico no autorizado a la red interna** |
| 4 | Block | any | IOT net | any | any | Sin Internet directo (los dispositivos IoT solo hablan con su broker) |

### IPsec (usuarios VPN, red 10.10.50.0/24)
| # | Acción | Proto | Origen | Destino | Puerto | Descripción |
|---|---|---|---|---|---|---|
| 1 | Pass | TCP | `VPN_NET` | `SRV_WEB` | 443 | Aplicación |
| 2 | Pass | TCP | `VPN_NET` | 172.16.20.10 | 445 | Servidor de archivos |
| 3 | Block | any | `VPN_NET` | any | any | Nada más (ni IoT ni gestión) |

Las reglas **INTERNA-2, DMZ-2, IOT-3 y VPN-3** son las que cumplen el requisito
"bloquear tráfico no autorizado a la VLAN red interna": solo entra lo que tiene una regla
*Pass* explícita y con estado (respuestas de sesiones iniciadas desde INTERNA).

## 4. VPN IPsec de acceso remoto (VPN > IPsec > Mobile Clients)

- *Mobile Clients*: Enable, User Authentication = Local Database, Virtual Address Pool
  10.10.50.0/24, Network List (split tunnel) = DMZ e INTERNA, DNS = 172.16.20.1.
- *Phase 1*: IKEv2, EAP-MSCHAPv2, AES-256-GCM, SHA-256, DH 14 (o 19/20), lifetime 28800,
  certificado de servidor emitido por una CA propia (*System > Cert Manager*).
- *Phase 2*: Tunnel IPv4, Local Network 0.0.0.0/0 (las reglas IPsec filtran), ESP
  AES-256-GCM, PFS 14, lifetime 3600.
- Usuarios en *System > User Manager* con privilegio "User - VPN: IPsec xauth Dialin".

## 5. Filtrado de contenido: bloquear dominios de phishing (pfBlockerNG-devel)

1. *System > Package Manager > Available Packages*: instalar **pfBlockerNG-devel**.
2. *Firewall > pfBlockerNG > General*: Enable, Keep Settings. *DNSBL*: Enable DNSBL,
   modo **Unbound python mode**, DNSBL VIP 10.10.10.1, *Permit Firewall Rules* en
   INTERNA e IOT.
3. *DNSBL > DNSBL Groups > Add* — nombre `Phishing`, acción **Unbound**, fuentes:
   | Header | URL | Formato |
   |---|---|---|
   | OpenPhish | `https://openphish.com/feed.txt` | Auto |
   | URLhaus | `https://urlhaus.abuse.ch/downloads/hostfile/` | Auto |
   | Phishing_Army | `https://phishing.army/download/phishing_army_blocklist.txt` | Auto |
   y en *DNSBL Custom_List* pega [`phishing-dominios.txt`](phishing-dominios.txt).
4. *Update > Force > Reload > All* y espera a que termine.
5. Regla INTERNA-4 (bloqueo de DNS externo) asegura que el cliente use el resolver.

**Validación** desde la PC INTERNA:
```bash
nslookup login-banco-seguro-mx.com      # -> 10.10.10.1 (VIP de DNSBL) = bloqueado
nslookup www.unam.mx                     # -> IP real = permitido
nslookup login-banco-seguro-mx.com 8.8.8.8   # -> timeout: la regla INTERNA-4 lo impide
```
En *Reports > Alerts > DNSBL* aparece el dominio, la IP del cliente y el grupo `Phishing`.

## 6. Snort IDS/IPS (Services > Snort)

1. Instalar el paquete **snort** (Snort 2.9.x, misma rama que el laboratorio en contenedor).
2. *Global Settings*: Snort VRT (Oinkcode gratuito) + Snort GPLv2 Community + ET Open;
   update interval 12 h; *Remove Blocked Hosts Interval* = 1 hour.
3. *Snort Interfaces > Add* — **WAN** y **DMZ**:
   - Enable, *Send Alerts to System Log*.
   - **Block Offenders** = ✔, **IPS Mode = Legacy Mode**, *Which IP to Block* = SRC
     (en Inline Mode con netmap se descartan los paquetes en vez de bloquear la IP).
   - *Preprocessors > Portscan Detection* ✔, sensitivity Medium.
   - *Pass Lists*: incluye la IP de PC_ADMIN y el gateway para no bloquearlos por error.
4. *WAN Rules > Category = custom.rules*: pegar
   [`../lab-snort/rules/act4-portscan.rules`](../lab-snort/rules/act4-portscan.rules)
   (cambiar `$EXTERNAL_NET`/`$HOME_NET` si se desea) → Save → reiniciar la interfaz.

**Validación con nmap** desde el atacante (WAN):
```bash
sudo nmap -Pn -sS -T4 -p 1-1000 <IP-WAN-pfSense>
sudo nmap -Pn -sX -p 1-200 <IP-WAN-pfSense>
sudo nmap -Pn -sS -p 22,80,443 <IP-WAN-pfSense>    # segundo intento: todo "filtered"
```
Evidencias: *Services > Snort > Alerts* (SID 1000001/1000005 y 122:x de sfPortscan) y
*Services > Snort > Blocked* con la IP del atacante. El resultado esperado es el mismo que
obtuvo el laboratorio reproducible en contenedores
([`../docs/evidencias/snort-nmap.txt`](../docs/evidencias/snort-nmap.txt)).

## 7. Copia de la configuración

*Diagnostics > Backup & Restore > Download configuration as XML* y guarda `config-act4.xml`
fuera del repositorio (contiene hashes de contraseñas y la PSK/certificados de la VPN).

## Implementación probada

Estas reglas están implementadas y validadas con tráfico real en [`../lab-perimetro`](../lab-perimetro).
