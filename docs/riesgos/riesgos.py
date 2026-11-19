"""Registro de riesgos de la Act4: fuente única para la matriz 5x5 y el reporte.
P = probabilidad (1 rara .. 5 casi segura) · I = impacto (1 insignificante .. 5 catastrófico)
"""
RIESGOS = [
 # id, amenaza, activo, P, I, mitigación, P_res, I_res, evidencia
 ("R1", "Inyección SQL (A03) en DVWA /sqli", "BD de usuarios de la app web", 5, 5,
  "Consultas parametrizadas, validación por lista blanca, usuario de BD de solo lectura, WAF/Snort con reglas SQLi", 1, 4, "ZAP 40018 + UNION con hashes"),
 ("R2", "Control de acceso roto (A01) en DVWA /authbypass", "Datos y cuentas de usuarios", 4, 5,
  "Autorización del lado del servidor en cada endpoint (deny by default), pruebas de IDOR, registro de accesos", 1, 4, "gordonb lee y modifica al admin"),
 ("R3", "XSS reflejado (A03) en DVWA /xss_r", "Sesiones de usuarios", 4, 4,
  "Codificación de salida por contexto, CSP sin unsafe-inline, cookies HttpOnly+Secure+SameSite", 1, 3, "ZAP 40012 + payload sin codificar"),
 ("R4", "JWT mal configurado (alg=none / secreto débil)", "API: identidad y roles", 4, 5,
  "RS256 con lista blanca de algoritmos, exp/aud/iss obligatorios, TTL 15 min, llaves en vault y rotación (kid/JWKS)", 1, 4, "Ataque OK en app_vulnerable, 401 en app.py"),
 ("R5", "Inyección SQL en la API (parámetros y cuerpo)", "BD de inventario", 4, 5,
  "Validación de esquema estricto + SQL parametrizado + errores genéricos", 1, 3, "UNION OK en vulnerable, 400 en segura"),
 ("R6", "Abuso de API / fuerza bruta sin límite de tasa", "Disponibilidad y credenciales", 4, 3,
  "Rate limiting 100/min por cliente con Retry-After, límite por IP en el borde, alertas", 2, 2, "solicitud 101 -> 429"),
 ("R7", "Movimiento lateral desde IoT o DMZ comprometida", "Red interna", 3, 5,
  "VLAN + ACL/pfSense deny DMZ->INTERNA e IOT->INTERNA, IoT sin Internet, port-security", 1, 4, "Pruebas 3 y 4 de Packet Tracer"),
 ("R8", "Reconocimiento con escaneo de puertos (nmap)", "Superficie de red", 5, 2,
  "Snort reglas 1000001-1000007 + sfPortscan, Block Offenders, solo 443/IPsec expuestos", 3, 1, "alert.fast + bloqueo IPS"),
 ("R9", "Phishing por dominios fraudulentos", "Credenciales de usuarios", 5, 4,
  "pfBlockerNG DNSBL (OpenPhish, URLhaus), bloqueo de DNS externo, MFA, capacitación", 3, 2, "nslookup -> VIP DNSBL"),
 ("R10", "Acceso remoto inseguro (servicios expuestos)", "Red interna", 3, 5,
  "VPN IPsec AES-256 con usuario+PSK/certificado, split tunnel mínimo, sin RDP/SSH público", 1, 4, "show crypto ipsec sa"),
 ("R11", "Configuración insegura: cabeceras y cookies (A05)", "Aplicación web", 4, 2,
  "CSP, X-Frame-Options, HttpOnly/SameSite, ocultar versión del servidor", 2, 1, "Alertas pasivas de ZAP"),
]


def nivel(p, i):
    s = p * i
    if s >= 20:
        return "Crítico"
    if s >= 10:
        return "Alto"
    if s >= 5:
        return "Medio"
    return "Bajo"
