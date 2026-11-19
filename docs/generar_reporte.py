"""Genera docs/Act4_Ciberseguridad_Santiago_Gonzalez_Ponce_AL03088820.docx a partir de las
evidencias reales del repositorio (salidas de ZAP, pruebas, Snort) y del registro de riesgos.
Uso: python3 docs/generar_reporte.py   (requiere python-docx)
"""
import json
import re
import sys
from collections import Counter
from pathlib import Path

from docx import Document
from docx.enum.section import WD_ORIENT  # noqa: F401
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_BREAK
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Cm, Pt, RGBColor

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
EV = DOCS / "evidencias"
sys.path.insert(0, str(DOCS / "riesgos"))
from riesgos import RIESGOS, nivel  # noqa: E402

FECHA = "18 de noviembre de 2026"
REPO = "https://github.com/SantiagoGzzPonce/act4-ciberseguridad-santiago-gonzalez-ponce-al03088820"
OUT = DOCS / "Act4_Ciberseguridad_Santiago_Gonzalez_Ponce_AL03088820.docx"

doc = Document()
sec = doc.sections[0]
sec.page_width, sec.page_height = Cm(21.59), Cm(27.94)
for side in ("left_margin", "right_margin"):
    setattr(sec, side, Cm(2.3))
sec.top_margin = sec.bottom_margin = Cm(2.2)

st = doc.styles["Normal"]
st.font.name = "Calibri"
st.font.size = Pt(11)
st.paragraph_format.space_after = Pt(6)
st.paragraph_format.line_spacing = 1.15
for name, size, color in (("Heading 1", 16, "1F3864"), ("Heading 2", 13, "2E74B5"), ("Heading 3", 11.5, "2E74B5")):
    h = doc.styles[name]
    h.font.name = "Calibri"
    h.font.size = Pt(size)
    h.font.color.rgb = RGBColor.from_string(color)
    h.paragraph_format.space_before = Pt(14 if name == "Heading 1" else 10)
    h.paragraph_format.space_after = Pt(6)
    h.paragraph_format.keep_with_next = True

fig_n = [0]
tab_n = [0]


# ------------------------------------------------------------------ utilidades
def shade(cell, hexcolor):
    tcPr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), hexcolor)
    tcPr.append(shd)


def P(text="", bold=False, italic=False, size=None, align=None, after=None, color=None, style=None):
    p = doc.add_paragraph(style=style)
    if text:
        add_runs(p, text, bold=bold, italic=italic, size=size, color=color)
    if align:
        p.alignment = align
    if after is not None:
        p.paragraph_format.space_after = Pt(after)
    return p


def add_runs(p, text, bold=False, italic=False, size=None, color=None):
    """Admite **negritas**, *cursivas* y `código` en línea."""
    for part in re.split(r"(\*\*[^*]+\*\*|`[^`]+`|(?<![\w*])\*[^*\s][^*]*?\*(?![\w*]))", text):
        if not part:
            continue
        if part.startswith("**"):
            r = p.add_run(part[2:-2])
            r.bold = True
        elif part.startswith("*") and len(part) > 2:
            r = p.add_run(part[1:-1])
            r.italic = True
        elif part.startswith("`"):
            r = p.add_run(part[1:-1])
            r.font.name = "Consolas"
            r.font.size = Pt(9.5)
            r.font.color.rgb = RGBColor(0x9C, 0x27, 0x2B)
        else:
            r = p.add_run(part)
            r.bold = bold or None
        r.italic = r.italic or italic or None
        if size and not part.startswith("`"):
            r.font.size = Pt(size)
        if color:
            r.font.color.rgb = RGBColor.from_string(color)
    return p


def bullets(items, style="List Bullet"):
    for it in items:
        p = doc.add_paragraph(style=style)
        add_runs(p, it)
        p.paragraph_format.space_after = Pt(2)


def H(text, level=1):
    return doc.add_heading(text, level=level)


def code(text, size=8.5, max_lines=None):
    lines = text.rstrip("\n").splitlines()
    if max_lines and len(lines) > max_lines:
        lines = lines[:max_lines] + [f"... ({len(text.splitlines()) - max_lines} líneas más en el archivo de evidencia)"]
    t = doc.add_table(rows=1, cols=1)
    t.alignment = WD_TABLE_ALIGNMENT.CENTER
    c = t.rows[0].cells[0]
    shade(c, "F3F4F6")
    c.paragraphs[0].text = ""
    p = c.paragraphs[0]
    p.paragraph_format.space_after = Pt(0)
    p.paragraph_format.line_spacing = 1.0
    for i, ln in enumerate(lines):
        r = p.add_run(ln)
        r.font.name = "Consolas"
        r._element.rPr.rFonts.set(qn("w:eastAsia"), "Consolas")
        r.font.size = Pt(size)
        if i < len(lines) - 1:
            r.add_break()
    doc.add_paragraph().paragraph_format.space_after = Pt(2)


def caption(kind, text):
    if kind == "Figura":
        fig_n[0] += 1
        n = fig_n[0]
    else:
        tab_n[0] += 1
        n = tab_n[0]
    p = P(f"{kind} {n}. {text}", italic=True, size=9.5, align=WD_ALIGN_PARAGRAPH.CENTER, color="404040")
    return p


def figure(path, text, width=16):
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.add_run().add_picture(str(path), width=Cm(width))
    p.paragraph_format.keep_with_next = True
    caption("Figura", text)


def placeholder(text):
    """Recuadro amarillo para capturas que el alumno toma en Packet Tracer / pfSense / Postman."""
    t = doc.add_table(rows=1, cols=1)
    t.alignment = WD_TABLE_ALIGNMENT.CENTER
    c = t.rows[0].cells[0]
    shade(c, "FFF4CE")
    c.paragraphs[0].text = ""
    add_runs(c.paragraphs[0], "[Insertar captura] " + text, italic=True, size=10, color="7A5A00")
    doc.add_paragraph().paragraph_format.space_after = Pt(2)


def table(headers, rows, widths=None, size=9, header_fill="1F3864", zebra=True, fills=None):
    t = doc.add_table(rows=1, cols=len(headers))
    t.style = "Table Grid"
    t.alignment = WD_TABLE_ALIGNMENT.CENTER
    for i, h in enumerate(headers):
        c = t.rows[0].cells[i]
        c.text = ""
        r = c.paragraphs[0].add_run(h)
        r.bold = True
        r.font.size = Pt(size)
        r.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
        shade(c, header_fill)
    for ri, row in enumerate(rows):
        cells = t.add_row().cells
        for i, val in enumerate(row):
            cells[i].text = ""
            p = cells[i].paragraphs[0]
            p.paragraph_format.space_after = Pt(0)
            add_runs(p, str(val), size=size)
            if fills and fills.get((ri, i)):
                shade(cells[i], fills[(ri, i)])
            elif zebra and ri % 2:
                shade(cells[i], "F2F5FA")
    # repetir encabezado
    trPr = t.rows[0]._tr.get_or_add_trPr()
    el = OxmlElement("w:tblHeader")
    el.set(qn("w:val"), "true")
    trPr.append(el)
    if widths:
        for row in t.rows:
            for i, w in enumerate(widths):
                row.cells[i].width = Cm(w)
    doc.add_paragraph().paragraph_format.space_after = Pt(2)
    return t


def read(path):
    return (ROOT / path).read_text(encoding="utf-8", errors="replace")


NIVEL_FILL = {"Crítico": "F4C7C7", "Alto": "FAD9C9", "Medio": "FDEBC0", "Bajo": "CDEFC8"}

# Sin portada: el alumno agrega la suya.

# =================================================================== INTRODUCCIÓN
H("Introducción")
P("Esta actividad recorre la defensa en profundidad de una organización pequeña, desde la "
  "aplicación hasta el borde de la red: se buscan vulnerabilidades reales en una aplicación web "
  "(DVWA) con OWASP ZAP, se construye y prueba una API protegida con OAuth 2.0, JWT, validación de "
  "entradas y límite de tasa, se diseña una red segmentada en tres VLAN con VPN IPsec, se definen "
  "las reglas del firewall perimetral (pfSense) con filtrado de phishing y un IDS/IPS (Snort) que "
  "detecta y bloquea escaneos de nmap, y por último se priorizan todas las amenazas en una matriz 5×5.")
P("Las partes que pueden contenerse se ejecutaron de verdad en contenedores Podman *rootless* en "
  "Linux (Bazzite/Fedora): DVWA + MariaDB, OWASP ZAP, la API, Snort 2.9 y un contenedor atacante con "
  "nmap, además de un firewall perimetral con las reglas de pfSense traducidas a nftables. Todos los puertos "
  "se publican solo en `127.0.0.1` o en redes internas sin salida. Las salidas que se citan en este reporte "
  "son las reales y están completas en `docs/evidencias/`. Packet Tracer no corre en contenedor: para la red "
  "se entregan el diagrama, las configuraciones completas de cada equipo, la guía de armado y las pruebas.")
P(f"Repositorio con el código, las configuraciones y las evidencias: {REPO}", size=10, color="2E74B5")

table(["Paso", "Herramienta / entorno", "Resultado principal"], [
    ["1. Vulnerabilidades web", "DVWA (digininja, PHP 8.5) + OWASP ZAP stable (Automation Framework)", "SQLi, XSS reflejado y control de acceso roto confirmados"],
    ["2. Protección de API", "Flask 3.1 + PyJWT 2.10 (RS256), Postman/Insomnia, curl", "25/25 pruebas; 401/403/400/429 según el ataque"],
    ["3. Red segura", "Cisco Packet Tracer 8.2 (2911, 2960)", "3 VLAN + gestión, ACL de mínimo privilegio, VPN IPsec"],
    ["4. Perímetro", "Diseño en pfSense CE 2.7; implementación equivalente con nftables + dnsmasq (DNSBL) + Snort 2.9.20; nmap 7.94", "23/23 pruebas de reglas y phishing; atacante bloqueado en 1 s"],
    ["5. Riesgos", "Matriz 5×5 (probabilidad × impacto)", "11 riesgos: 5 críticos → 0 tras mitigar"],
], widths=[3.5, 6.5, 6.5])
caption("Tabla", "Resumen de la actividad.")

# =================================================================== 1. DVWA + ZAP
H("1. Análisis de vulnerabilidades en la aplicación web")
H("1.1 Entorno y escaneo con OWASP ZAP", 2)
P("DVWA se levantó con `podman compose` (archivo `lab-dvwa-zap/compose.yaml`) junto a MariaDB 11.4 en "
  "una red aislada `act4-lab`. El script `preparar-dvwa.sh` crea la base de datos, inicia sesión con la "
  "cuenta de laboratorio y fija el nivel de seguridad en *low*. ZAP se ejecutó con su Automation "
  "Framework (`zap-plan.yaml.tpl`) dentro de la misma red: una regla *replacer* inyecta la cookie de "
  "sesión para que el escaneo sea autenticado; se excluyeron `logout`, `setup`, `security.php` y "
  "`csrf` para que el escáner no cerrara la sesión ni reiniciara la base. Trabajos: spider → "
  "solicitudes semilla → escaneo pasivo → escaneo activo (máx. 12 min) → reportes HTML, JSON y Markdown.")

ZAP_JSON = ROOT / "lab-dvwa-zap/reportes/zap-dvwa.json"
zap_rows, zap_counts = [], Counter()
if ZAP_JSON.exists():
    data = json.loads(ZAP_JSON.read_text())
    alerts = []
    for site in data.get("site", []):
        alerts += site.get("alerts", [])
    risk_name = {"3": "Alto", "2": "Medio", "1": "Bajo", "0": "Informativo"}
    alerts.sort(key=lambda a: (-int(a.get("riskcode", 0)), a.get("name", "")))
    for a in alerts:
        rn = risk_name.get(str(a.get("riskcode")), "?")
        zap_counts[rn] += 1
        inst = a.get("instances", [])
        uri = inst[0].get("uri", "") if inst else ""
        param = inst[0].get("param", "") if inst else ""
        zap_rows.append([rn, a.get("name", ""), a.get("pluginid", ""), f"CWE-{a.get('cweid', '')}",
                         str(a.get("count", len(inst))), "`" + re.sub(r"^http://dvwa", "", uri)[:60].replace("`", "'") + "`" + (f" ({param})" if param else "")])
zap_rows = [r for r in zap_rows if r[0] in ("Alto", "Medio")]
fills = {(i, 0): {"Alto": "F4C7C7", "Medio": "FAD9C9"}.get(r[0]) for i, r in enumerate(zap_rows)}
P(f"Resultado: **{sum(zap_counts.values())} tipos de alerta** — "
  + ", ".join(f"{zap_counts[k]} de riesgo {k.lower()}" for k in ("Alto", "Medio", "Bajo", "Informativo") if zap_counts[k])
  + ". La tabla lista las de riesgo alto y medio; las bajas e informativas (cabeceras faltantes, "
  "versión del servidor en `Server` y `X-Powered-By`, cookies sin `HttpOnly`/`SameSite`, `phpinfo.php` expuesto) "
  "están en el reporte completo `lab-dvwa-zap/reportes/zap-dvwa.html`. Aunque el plan limitaba el escaneo activo a "
  "unos módulos, el spider siguió los enlaces del menú y ZAP también probó otros módulos (fuerza bruta, CAPTCHA, "
  "redirección abierta); por eso aparecen alertas fuera de la lista inicial.")
table(["Riesgo", "Alerta de ZAP", "Plugin", "CWE", "Inst.", "Ejemplo (URL / parámetro)"], zap_rows,
      widths=[1.8, 5.2, 1.3, 1.6, 1.0, 6.0], size=8, fills=fills, zebra=False)
caption("Tabla", "Alertas de riesgo alto y medio de OWASP ZAP sobre DVWA (nivel low, sesión autenticada).")
P("**Lo que ZAP no detectó.** El control de acceso roto de `/authbypass/` no aparece en ninguna alerta: un escáner "
  "no sabe qué usuario *debería* poder ver qué dato, porque la autorización depende de reglas del negocio. Por eso "
  "la tercera vulnerabilidad se encontró a mano, comparando las respuestas de un usuario normal y de un administrador.")
figure(EV / "zap-reporte.png", "Reporte HTML de OWASP ZAP 2.17.0 sobre DVWA: 9 alertas altas, 12 medias, 10 bajas y 7 informativas.", width=16)

H("1.2 Confirmación manual de tres vulnerabilidades OWASP Top 10", 2)
P("Un hallazgo de escáner no es una vulnerabilidad hasta que se explota. `confirmar-vulnerabilidades.sh` "
  "reproduce cada una con curl; la salida completa está en `docs/evidencias/dvwa-confirmacion-manual.txt`.")
code(read("docs/evidencias/dvwa-confirmacion-manual.txt"), size=7.5)
caption("Figura", "Explotación manual de SQLi, XSS reflejado y control de acceso roto en DVWA.")

H("1.3 Evaluación de riesgos (plantilla)", 2)
P("Cada vulnerabilidad se documentó con la misma plantilla: vector de ataque, impacto en "
  "confidencialidad/integridad/disponibilidad (CIA), probabilidad e impacto en escala 1–5 y nivel resultante.")

PLANTILLAS = [
    ("V1 — Inyección SQL", [
        ("OWASP / CWE", "A03:2021 Injection · CWE-89"),
        ("Ubicación", "`/vulnerabilities/sqli/?id=` (GET), confirmada a mano. ZAP la detectó con el plugin 40018 en los módulos hermanos `/sqli_blind/?id=` y `/brute/?username=`, que comparten el mismo patrón de SQL concatenado."),
        ("Vector de ataque", "El parámetro `id` se concatena en `SELECT first_name, last_name FROM users WHERE user_id = '$id'`. "
         "Con `1' OR '1'='1` la condición siempre es verdadera; con `' UNION SELECT user, password FROM users#` se "
         "anexan columnas de otra tabla. No requiere más que un navegador."),
        ("Evidencia", "Se obtuvieron los 5 usuarios con su hash MD5 sin sal (p. ej. `admin : 5f4dcc3b5aa765d61d8327deb882cf99` = «password», "
         "reversible con cualquier tabla arcoíris) y la versión `11.4.13-MariaDB`."),
        ("Impacto (CIA)", "C: alta (volcado completo de la BD) · I: alta (con permisos de escritura, `UPDATE`/`DROP`) · D: media."),
        ("Probabilidad × Impacto", "5 × 5 = **25 · Crítico**"),
        ("Mitigación", "Consultas parametrizadas (PDO `prepare`), validación del tipo (`id` entero), usuario de BD con mínimo "
         "privilegio, contraseñas con Argon2/bcrypt, errores genéricos y regla IDS/WAF para patrones SQLi."),
    ]),
    ("V2 — Cross-Site Scripting reflejado", [
        ("OWASP / CWE", "A03:2021 Injection · CWE-79"),
        ("Ubicación", "`/vulnerabilities/xss_r/?name=` (GET). ZAP: *Cross Site Scripting (Reflected)* (plugin 40012, 4 instancias) y además *DOM Based* (40026) en `/xss_d/`."),
        ("Vector de ataque", "El valor de `name` se imprime sin codificar en `Hello <name>`. El atacante envía a la víctima un "
         "enlace con `<script>…</script>` (correo, chat); el código corre en el origen de DVWA con la sesión de la víctima."),
        ("Evidencia", "El payload `<script>alert(document.cookie)</script>` regresa literal en la respuesta, y la cookie "
         "`PHPSESSID` se emite sin `HttpOnly` ni `SameSite`, por lo que `document.cookie` la expone."),
        ("Impacto (CIA)", "C: alta (robo de sesión, *keylogging*) · I: media (acciones en nombre de la víctima, *defacement*) · D: baja."),
        ("Probabilidad × Impacto", "4 × 4 = **16 · Alto**"),
        ("Mitigación", "Codificación de salida según contexto (`htmlspecialchars` con ENT_QUOTES), Content-Security-Policy sin "
         "`unsafe-inline`, cookies `HttpOnly; Secure; SameSite=Lax` y validación de entrada por lista blanca."),
    ]),
    ("V3 — Control de acceso roto", [
        ("OWASP / CWE", "A01:2021 Broken Access Control · CWE-285 / CWE-639"),
        ("Ubicación", "`/vulnerabilities/authbypass/get_user_data.php` y `change_user_details.php` (API JSON detrás de la página de administración). No la reporta ZAP: se encontró con prueba manual por roles."),
        ("Vector de ataque", "La página solo oculta el menú a los no administradores, pero los endpoints que usa no verifican el rol. "
         "Un usuario normal (`gordonb`) llama directamente a la API."),
        ("Evidencia", "Con la sesión de gordonb: `get_user_data.php` → HTTP 200 con todos los usuarios; "
         "`change_user_details.php` con `{\"id\":1,…}` → `{\"result\":\"ok\"}` y el administrador queda renombrado «Hacked ByGordon» (se restauró después)."),
        ("Impacto (CIA)", "C: alta (datos de todos los usuarios) · I: alta (modificación de cuentas ajenas, incluida la del admin) · D: baja."),
        ("Probabilidad × Impacto", "4 × 5 = **20 · Crítico**"),
        ("Mitigación", "Autorización del lado del servidor en **cada** endpoint con *deny by default*, comprobar propiedad del "
         "recurso (anti-IDOR), pruebas automatizadas por rol y registro/alerta de accesos denegados."),
    ]),
]
for titulo, filas in PLANTILLAS:
    H(titulo, 3)
    t = doc.add_table(rows=0, cols=2)
    t.style = "Table Grid"
    for k, v in filas:
        cells = t.add_row().cells
        cells[0].text = ""
        r = cells[0].paragraphs[0].add_run(k)
        r.bold = True
        r.font.size = Pt(9)
        shade(cells[0], "DCE6F2")
        cells[1].text = ""
        add_runs(cells[1].paragraphs[0], v, size=9)
        if k.startswith("Probabilidad"):
            lvl = "Crítico" if "Crítico" in v else "Alto"
            shade(cells[1], NIVEL_FILL[lvl])
        cells[0].width, cells[1].width = Cm(3.6), Cm(13.0)
    doc.add_paragraph().paragraph_format.space_after = Pt(2)

# =================================================================== 2. API
H("2. Protección de las API")
H("2.1 Escenario generado con IA", 2)
P("Se tomó como base el prompt sugerido: *«Genera un escenario de ataque a una API que use inyección SQL y "
  "JWT mal configurado. Incluye vector de ataque, impacto y dos recomendaciones de mitigación»*. La "
  "respuesta íntegra de DeepSeek está en `docs/auditoria-ia/respuesta-deepseek.md` y su auditoría en `docs/bitacora-ia.md`. El escenario se convirtió en código: "
  "`app_vulnerable.py` reproduce exactamente esas fallas y `app.py` es la versión corregida, de modo que el "
  "ataque y la defensa se pueden ejecutar uno contra otra.")
BITACORA = DOCS / "bitacora-ia.md"
btxt = BITACORA.read_text() if BITACORA.exists() else "PENDIENTE"
if "PENDIENTE" not in btxt:
    figure(EV / "ia-conversacion.png", "Prompt enviado a DeepSeek (chat web, Smart Search: 13 páginas) y el inicio de su respuesta.", width=15)
    P("**Lo que la IA hizo bien.** Respetó el formato pedido (vector, impacto y dos mitigaciones), identificó las "
      "dos fallas clásicas de JWT (`alg=none` y secreto HS256 débil roto por diccionario), insistió en que el "
      "algoritmo lo fija el servidor y no el header, y recomendó RS256/ES256, claves de alta entropía, validar "
      "`exp/iss/aud/nbf`, tokens de 15–60 min y mínimo privilegio en la base de datos.")
    P("**Omisiones y errores.** La auditoría completa está en `docs/bitacora-ia.md`:", after=2)
    sec4 = re.search(r"## 4\..*?\n(.*?)(\n## |\Z)", btxt, re.S).group(1)
    filas = []
    for ln in sec4.splitlines():
        cols = [c.strip() for c in ln.strip().strip("|").split("|")]
        if len(cols) == 4 and cols[0].isdigit():
            filas.append(cols)
    table(["#", "Tema", "Hallazgo", "Corrección"], filas, widths=[0.7, 2.8, 7.6, 5.5], size=8)
    caption("Tabla", "Errores y omisiones de la respuesta de DeepSeek.")
    P("Las correcciones 1–8 se aplicaron en `app.py`; el escenario de la IA se reprodujo en `app_vulnerable.py` "
      "(con la SQLi en un parámetro de búsqueda en lugar del login).")
else:
    placeholder("Captura de la conversación con la IA (prompt y respuesta). La auditoría se completa en docs/bitacora-ia.md.")

H("2.2 Ataque contra la versión vulnerable", 2)
code(read("docs/evidencias/api-ataque-vulnerable-vs-segura.txt"), size=7.5)
caption("Figura", "SQLi UNION, error de BD expuesto, token alg=none y firma con secreto de diccionario: los cuatro "
        "funcionan contra app_vulnerable.py y los mismos tokens reciben 401 en app.py.")

H("2.3 Autenticación: OAuth 2.0 + JWT", 2)
P("La API simula los dos papeles de OAuth 2.0 en un solo servicio: **servidor de autorización** "
  "(`POST /oauth/token`, flujo *client credentials* de RFC 6749 §4.4) y **servidor de recursos** "
  "(`/api/productos`). Se eligió *client credentials* porque el consumidor es otra aplicación (máquina a "
  "máquina); el flujo *password* se rechaza (`unsupported_grant_type`) porque OAuth 2.1 lo elimina.")
table(["Control", "Implementación en app.py", "Ataque que evita"], [
    ["Autenticación del cliente", "HTTP Basic; secretos de 32 bytes aleatorios en `.env`, guardados como PBKDF2-SHA256 (200 000 iteraciones) y comparados con `hmac.compare_digest`", "Robo de secretos en texto plano, ataques de tiempo"],
    ["Firma asimétrica", "RS256 con RSA-3072; la llave privada se crea al iniciar (600) y la pública se publica en `/.well-known/jwks.json` con `kid`", "Falsificar tokens si se filtra el secreto de verificación (HS256 compartido)"],
    ["Lista blanca de algoritmos", "`jwt.decode(..., algorithms=[\"RS256\"])`", "`alg=none` y confusión RS256→HS256 usando la llave pública como secreto"],
    ["Claims obligatorios", "`exp` (15 min), `iat`, `nbf`, `iss`, `aud`, `sub`, `jti`; tolerancia de reloj 30 s", "Reutilizar tokens viejos o emitidos para otra API"],
    ["Scopes", "`productos:read` / `productos:write`; el cliente solo puede pedir los suyos (`invalid_scope`) y el endpoint responde 403", "Escalamiento de privilegios (un lector que crea productos)"],
    ["Errores", "401 con `WWW-Authenticate: Bearer error=...`, sin trazas", "Enumeración y fuga de información"],
], widths=[3.3, 8.2, 5.1], size=8.5)
caption("Tabla", "Controles de autenticación y autorización.")

H("2.4 Validación de entradas contra inyección", 2)
P("Se aplican dos capas independientes: (1) **validación por lista blanca** antes de tocar la base —`categoria` "
  "debe pertenecer a {redes, iot, software}, el `id` de la ruta debe cumplir `^[1-9][0-9]{0,8}$`, y el cuerpo de "
  "`POST` solo admite los cuatro campos esperados con tipo, longitud, rango y expresión regular (se rechazan "
  "campos extra como `rol` para evitar *mass assignment*, y `True` como entero); y (2) **SQL parametrizado** "
  "(`WHERE categoria = ?`), de modo que aunque un valor pasara la validación nunca se interpreta como SQL. "
  "Además, el cuerpo está limitado a 16 KB (413) y los errores son genéricos.")

H("2.5 Rate limiting (100 solicitudes/minuto)", 2)
P("Ventana deslizante en memoria por cliente: la clave es el `sub` de un JWT **con firma válida** y, si no hay "
  "token válido, la IP. Esto importa: en la primera versión se contaba por el `sub` sin verificar, y un atacante "
  "podía inventar un `sub` distinto en cada solicitud para no llegar nunca al límite; la prueba "
  "`test_33_sub_falsificado_no_evade_limite` cubre ese caso. Al exceder el límite se responde **429** con "
  "`Retry-After` y `X-RateLimit-Limit/Remaining`. En producción con varios *workers* el contador iría en Redis.")

H("2.6 Pruebas", 2)
P("Pruebas unitarias (`tests/test_api.py`), ejecutadas con la API corriendo en un contenedor de solo lectura, "
  "sin capacidades y como usuario 10001:")
code(read("docs/evidencias/api-pruebas-unitarias.txt"), size=7.5)
caption("Figura", "25 pruebas: OAuth/JWT, validación, rate limiting y demostración del ataque a la versión vulnerable.")
P("Prueba de punta a punta con curl contra el contenedor (`probar.sh`):")
code(read("docs/evidencias/api-probar.txt"), size=7.5)
caption("Figura", "Flujo OAuth → JWT RS256 y respuestas 401/403/400/429. Las 6 solicitudes previas del mismo cliente "
        "cuentan dentro de la ventana, por eso el bucle de 120 recibe 94 respuestas 200 (100 en total) y 26 respuestas 429.")
P("La colección `postman/act4-api-segura.postman_collection.json` (importable en Postman e Insomnia) usa "
  "autorización OAuth 2.0 a nivel colección, guarda el token en una variable y trae pruebas en cada petición; "
  "la petición 6 se corre en el *Runner* con 101 iteraciones para observar el 429.")
figure(EV / "postman-token.png", "Postman: token OAuth 2.0 (client_credentials) emitido como JWT RS256 con vida de 900 s y scope productos:read; prueba 1/1 en verde.", width=16)
figure(EV / "postman-ratelimit.png", "Postman Runner con 101 iteraciones: las solicitudes 97 a 100 responden 200 y la 101 recibe 429 con el encabezado Retry-After.", width=12)

# =================================================================== 3. RED
H("3. Diseño de red segura")
P("La red se diseñó en Packet Tracer con un router de borde (ISR 2911 con licencia securityk9), un switch "
  "2960 y un router que simula al proveedor de Internet. Las configuraciones completas están en "
  "`red-segura/configs/` y la guía de armado con 11 pruebas en `red-segura/README.md`.")
figure(ROOT / "red-segura/diagrama-red.png", "Diagrama lógico de la red segmentada con los flujos permitidos y bloqueados.", width=16.5)
table(["VLAN", "Zona", "Red", "Equipos"], [
    ["10", "DMZ", "172.16.10.0/24", "SRV-WEB .10 (publicado en 200.10.10.2:443), SRV-DNS .11, BROKER-IOT .20"],
    ["20", "Red interna", "172.16.20.0/24", "SRV-ARCHIVOS .10, PC-ADMIN .50, PC-01/02 por DHCP"],
    ["30", "IoT", "172.16.30.0/24", "Cámara, sensor de humo, termostato por DHCP"],
    ["99", "Gestión (nativa)", "172.16.99.0/24", "SW-CORE .2"],
    ["—", "VPN", "10.10.50.0/24", "Pool de clientes IPsec"],
], widths=[1.3, 2.7, 3.2, 9.4])
caption("Tabla", "Plan de direccionamiento.")
H("3.1 VPN IPsec de acceso remoto", 2)
P("R-EDGE funciona como servidor Easy VPN (IKEv1): fase 1 con AES-256, SHA, llave precompartida de grupo y "
  "DH grupo 5 (el máximo que simula Packet Tracer); fase 2 con ESP AES-256 + HMAC-SHA. El usuario se autentica "
  "además con usuario y contraseña (XAUTH), recibe una IP del pool 10.10.50.0/24 y un **split tunnel** que "
  "solo enruta DMZ e INTERNA. Una ACL de salida en la subinterfaz de IoT descarta cualquier tráfico del pool "
  "VPN. En pfSense la misma VPN se define con IKEv2, AES-256-GCM y DH 14+.")

H("3.2 Justificación: principio de mínimo privilegio", 2)
P("Cada zona agrupa activos con el mismo nivel de confianza y recibe **solo** los flujos que su función "
  "requiere; todo lo demás termina en un *deny* con registro. Así, el compromiso de una zona no se convierte "
  "en el compromiso de toda la red.")
table(["Zona", "Lo que se permite", "Lo que se niega y por qué"], [
    ["DMZ", "Responder a clientes; salir a 80/443 (actualizaciones) y DNS", "Iniciar conexiones a INTERNA, IoT o gestión: es la zona expuesta (el Paso 1 mostró SQLi y XSS en una app de este tipo); si cae, el atacante queda contenido."],
    ["Red interna", "Web de la DMZ (443), DNS, Internet 80/443", "IoT y gestión, salvo PC-ADMIN: un equipo de usuario con malware no puede administrar la red ni tocar cámaras."],
    ["IoT", "Solo su broker MQTT/TLS (8883) y DNS", "Internet y la red interna: firmware sin parches y credenciales por defecto (Mirai); sin salida no hay movimiento lateral ni botnet."],
    ["Gestión", "SSH desde PC-ADMIN", "Todo lo demás; no se usa la VLAN 1 y los puertos libres están en la VLAN 999 apagados (anti VLAN hopping)."],
    ["VPN", "DMZ e INTERNA por split tunnel", "IoT y gestión: el usuario remoto obtiene lo mismo que uno interno, no más."],
], widths=[2.4, 5.2, 9.0], size=8.5)
caption("Tabla", "Aplicación del mínimo privilegio por zona.")
P("En capa 2 la segmentación se refuerza con troncal de VLAN explícitas sin DTP (`nonegotiate`), port-security "
  "con MAC *sticky*, BPDU guard y DHCP snooping; la administración usa SSH v2, contraseñas `scrypt`, "
  "`login block-for` y `access-class` limitado a PC-ADMIN y la VPN.")

# =================================================================== 4. PERÍMETRO
H("4. Implementación de seguridad perimetral")
P("El perímetro se diseñó para **pfSense CE 2.7** (reglas, alias, VPN, pfBlockerNG y Snort, con la guía paso a "
  "paso en `perimetro-pfsense/README.md`) y se **implementó y probó** en un firewall equivalente construido en "
  "contenedores (`lab-perimetro/`). pfSense corre sobre FreeBSD y no se puede contener; su motor de filtrado (pf) "
  "se tradujo regla por regla a **nftables**, el filtro de paquetes del kernel Linux, con las mismas interfaces, "
  "el mismo direccionamiento y la misma lógica: filtrado por interfaz de entrada, primera coincidencia gana, "
  "estado de conexión y bloqueo implícito al final. Así, cada regla del diseño se comprobó con tráfico real.")

H("4.1 Reglas de pfSense", 2)
P("Las reglas completas por interfaz (WAN, INTERNA, DMZ, IOT e IPsec) y los alias están en "
  "`perimetro-pfsense/README.md`; estas son las que protegen la red interna:")
table(["Interfaz", "#", "Acción", "Origen → Destino", "Puerto", "Propósito"], [
    ["DMZ", "2", "Block + log", "DMZ net → INTERNA net", "any", "Servidor expuesto comprometido no llega a la red interna"],
    ["IOT", "3", "Block + log", "IOT net → INTERNA net", "any", "Dispositivos IoT no alcanzan equipos de usuarios"],
    ["IOT", "4", "Block + log", "IOT net → any", "any", "Sin Internet directo (solo broker 8883 por la regla 2)"],
    ["IPsec", "3", "Block + log", "VPN_NET → any", "any", "Tras permitir solo 443 al web y 445 al servidor de archivos"],
    ["INTERNA", "4", "Block + log", "INTERNA net → any", "53, 853", "Impide saltarse el filtro DNS de phishing"],
    ["WAN", "—", "Block implícito", "any → any", "any", "Solo 443 (NAT a SRV-WEB), IKE 500/4500 y ESP están abiertos"],
], widths=[1.8, 0.8, 2.2, 4.2, 1.6, 6.0], size=8.5)
caption("Tabla", "Reglas que bloquean el tráfico no autorizado hacia la VLAN de red interna.")

H("4.2 Implementación en un firewall equivalente y validación", 2)
P("`lab-perimetro/levantar.sh` crea cuatro redes aisladas (sin salida real a Internet) y conecta el firewall a "
  "las cuatro, con la IP .1 de cada zona, igual que las interfaces em1.10/.20/.30 de pfSense:")
table(["Zona", "Red", "Equipos (contenedores)"], [
    ["WAN («Internet»)", "198.51.100.0/24", "Firewall .2 · sitio externo .80 · DNS público .53 · atacante .66"],
    ["DMZ", "172.16.10.0/24", "Firewall .1 · SRV-WEB .10 (80/443) · BROKER-IOT .20 (8883)"],
    ["INTERNA", "172.16.20.0/24", "Firewall .1 · SRV-ARCHIVOS .10 (445) · PC-ADMIN .50 · PC-01 .21"],
    ["IOT", "172.16.30.0/24", "Firewall .1 · CAM-01 .21 (443)"],
], widths=[3.2, 3.4, 10.0], size=8.5)
caption("Tabla", "Topología del laboratorio perimetral (mismo direccionamiento que el diseño).")
table(["En pfSense", "En el laboratorio", "Cómo se comprueba"], [
    ["Firewall > Rules (pf) por interfaz", "Cadenas `input`/`forward` de nftables con `iifname` por zona y la misma numeración (INTERNA-1 … IOT-4)", "`validar.sh`: 17 pruebas de conexión"],
    ["Firewall > NAT > Port Forward / Outbound", "`dnat` 443 → SRV-WEB y `masquerade` hacia la WAN", "Atacante llega solo al 443 publicado"],
    ["Columna *States* / System Logs > Firewall", "Contador de paquetes en cada regla", "Contadores tras las pruebas"],
    ["DNS Resolver + pfBlockerNG DNSBL", "dnsmasq: cada dominio de la lista responde la VIP 10.10.10.1", "6 consultas DNS"],
    ["Snort con *Block Offenders* (tabla `snort2c`)", "Snort 2.9 en la interfaz WAN + set `bloqueados` de nftables", "`ataque-snort.sh` con nmap"],
], widths=[4.6, 6.8, 5.2], size=8.5)
caption("Tabla", "Correspondencia entre pfSense y el firewall del laboratorio.")
fw_tpl = read("lab-perimetro/fw/reglas.nft.tpl")
fw_fwd = fw_tpl[fw_tpl.index("  chain forward"):fw_tpl.index("  # ---------------- NAT")].rstrip()
code(fw_fwd, size=7)
caption("Figura", "Cadena `forward` del firewall (lab-perimetro/fw/reglas.nft.tpl): las reglas de pfSense traducidas a nftables.")
val = read("docs/evidencias/perimetro-validacion.txt")
code(val[:val.index("=== 2.")].rstrip() + "\n\n" + val[val.index("=== 3."):val.index("=== 4.")].rstrip(), size=7)
caption("Figura", "Validación real de la segmentación: 17 de 17 pruebas con el resultado esperado y el contador de cada regla "
        "(equivale a los registros del firewall de pfSense). IoT y DMZ no alcanzan la red interna; solo PC-ADMIN administra.")

H("4.3 Filtrado de contenido: dominios de phishing", 2)
P("En pfSense se usa **pfBlockerNG-devel** en modo DNSBL con el grupo `Phishing` (feeds OpenPhish, URLhaus y "
  "Phishing Army, más la lista propia `phishing-dominios.txt`). Cuando un equipo pregunta por un dominio listado, "
  "el resolver responde con la IP virtual de DNSBL (10.10.10.1) en lugar de la real. En el laboratorio el resolver "
  "del firewall (dnsmasq) hace lo mismo con la misma lista, y la regla INTERNA-4 bloquea DNS (53) y DNS sobre TLS "
  "(853) hacia cualquier otro servidor para que el filtro no se pueda esquivar:")
code(val[val.index("=== 2."):val.index("Resultado:")].rstrip() + "\n\n" + val[val.index("=== 4."):].rstrip(), size=7)
caption("Figura", "Dominios de phishing (y sus subdominios) resueltos a la VIP de bloqueo desde INTERNA e IoT; dominios "
        "legítimos resueltos normal; consulta a un DNS externo bloqueada; registro de cada bloqueo con la IP del cliente.")

H("4.4 Snort: regla personalizada para escaneos de puertos", 2)
P("Se usó Snort 2.9.20, la misma rama que instala el paquete Snort de pfSense, para que las reglas se puedan "
  "pegar sin cambios en *custom.rules*. Las siete reglas (`lab-snort/rules/act4-portscan.rules`) cubren las "
  "técnicas de nmap; todas usan `threshold: type both` para generar **una** alerta por origen al superar el "
  "umbral en la ventana, en vez de una por paquete:")
rules_txt = "\n".join(ln for ln in read("lab-snort/rules/act4-portscan.rules").splitlines() if ln.startswith("alert"))
code(rules_txt, size=7)
caption("Figura", "Reglas personalizadas (SID 1000001–1000007).")
table(["SID", "Técnica de nmap", "Lógica de detección"], [
    ["1000001", "-sS (SYN)", "≥ 20 SYN sin ACK desde un mismo origen en 5 s (`flags:S,12` ignora los bits ECN)"],
    ["1000002", "-sT / puertos cerrados", "≥ 20 RST/ACK del servidor hacia el mismo destino en 5 s"],
    ["1000003–05", "-sN, -sF, -sX", "Combinaciones de banderas que ningún cliente legítimo usa (ninguna, FIN solo, FIN+PSH+URG)"],
    ["1000006", "-sV / -sC / NSE", "User-Agent «Nmap Scripting Engine» en la cabecera HTTP"],
    ["1000007", "-sn (ping sweep)", "≥ 10 ICMP echo desde un origen en 5 s"],
], widths=[2.2, 3.4, 11.0], size=8.5)
caption("Tabla", "Qué detecta cada regla.")
P("Complementa al preprocesador **sfPortscan** (sensibilidad media), que detecta barridos por estadística "
  "aunque el atacante vaya lento.")

H("4.5 Simulación del ataque con nmap y respuesta IDS/IPS", 2)
P("**Prueba 1 — Snort en la WAN del firewall (como en pfSense).** `lab-perimetro/ataque-snort.sh` pone Snort en la "
  "interfaz WAN del firewall. Al detectar un escaneo, agrega la IP de origen al set `bloqueados` de nftables, que "
  "cumple la misma función que la tabla `snort2c` de pfSense con *Block Offenders* (expira en 1 h, como el "
  "*Remove Blocked Hosts Interval*). Se comprueba antes, durante y después del ataque:")
code(read("docs/evidencias/perimetro-snort.txt"), size=7)
caption("Figura", "El atacante entra al sitio publicado; al escanear es detectado (SID 1000001 y sfPortscan) y bloqueado en "
        "el mismo segundo; después ya no obtiene respuesta, mientras otros clientes de Internet y la red interna siguen sin afectación.")
P("**Prueba 2 — Sensor frente al servidor DMZ, técnicas sigilosas.** `lab-snort/simular-ataque.sh` coloca el sensor "
  "en la interfaz del servidor DVWA (que no filtra puertos, así que nmap recibe RST y se activan más reglas) y "
  "lanza -sS, -sN, -sF, -sX y scripts NSE, cada técnica desde una IP nueva:")
SNORT_EV = EV / "snort-nmap.txt"
if SNORT_EV.exists():
    code(SNORT_EV.read_text(), size=6.5, max_lines=95)
    caption("Figura", "Seis reglas activadas (SYN, RST, NULL, FIN, XMAS y NSE), cada origen bloqueado y un cliente legítimo sin afectación.")

# =================================================================== 5. RIESGOS
H("5. Evaluación integral de riesgos")
P("Las amenazas encontradas en los cuatro pasos se valoraron con una matriz 5×5: probabilidad (1 rara … 5 casi "
  "segura) por impacto (1 insignificante … 5 catastrófico). Nivel: 1–4 bajo, 5–9 medio, 10–16 alto, 20–25 "
  "crítico. El riesgo **inherente** asume la configuración encontrada (sin controles); el **residual**, los "
  "controles de este reporte ya aplicados.")
figure(DOCS / "riesgos/matriz-riesgos.png", "Matriz 5×5: riesgo inherente frente a residual.", width=17)

orden = sorted(RIESGOS, key=lambda r: (-(r[3] * r[4]), -r[4]))
rows, fills = [], {}
for i, r in enumerate(orden, 1):
    inh, res = nivel(r[3], r[4]), nivel(r[6], r[7])
    rows.append([str(i), r[0], r[1], f"{r[3]}×{r[4]}={r[3] * r[4]}\n{inh}", r[5], f"{r[6]}×{r[7]}={r[6] * r[7]}\n{res}"])
    fills[(i - 1, 3)] = NIVEL_FILL[inh]
    fills[(i - 1, 5)] = NIVEL_FILL[res]
table(["Prio.", "ID", "Amenaza / vulnerabilidad", "Inherente", "Estrategia de mitigación", "Residual"], rows,
      widths=[1.0, 1.0, 4.2, 1.9, 6.6, 1.9], size=8, fills=fills, zebra=False)
caption("Tabla", "Registro de riesgos priorizado por nivel inherente (empate: mayor impacto primero).")

c_inh = Counter(nivel(r[3], r[4]) for r in RIESGOS)
c_res = Counter(nivel(r[6], r[7]) for r in RIESGOS)
P(f"**Lectura de la matriz.** Antes de mitigar hay {c_inh['Crítico']} riesgos críticos, {c_inh['Alto']} altos y "
  f"{c_inh['Medio']} medio; después quedan {c_res['Crítico']} críticos, {c_res['Alto']} altos, {c_res['Medio']} medio(s) y "
  f"{c_res['Bajo']} bajos. Los controles bajan sobre todo la **probabilidad** (corrigen la causa: SQL parametrizado, "
  "autorización en servidor, RS256); el impacto de un dato filtrado sigue siendo alto, por eso R1–R5 quedan en 4 y "
  "se justifican controles de detección (Snort, registros) y respuesta. Los riesgos que siguen en *medio*, como el "
  "phishing (R9), dependen de personas: DNSBL reduce la exposición, pero solo MFA y capacitación cierran la brecha.")
P("**Orden de atención propuesto.**", after=2)
bullets([
    "**Inmediato (críticos 20–25):** R1, R2, R4 y R5 — corregir el código (parametrizar, autorizar en servidor, "
    "fijar RS256 y rotar secretos) y, mientras se despliega, reglas de Snort/WAF como parche virtual. R9 — DNSBL ya, MFA después.",
    "**Corto plazo (altos 10–16):** R3 (codificación de salida + CSP + cookies), R7 y R10 (segmentación y VPN del Paso 3), "
    "R6 (rate limiting) y R8 (Snort con bloqueo).",
    "**Mantenimiento (medios/bajos):** R11 (cabeceras), actualización de feeds y firmas, revisión trimestral de reglas "
    "y de la matriz, y repetir el escaneo con ZAP en cada versión (DevSecOps).",
], style="List Number")

# =================================================================== CONCLUSIONES
H("Conclusiones")
P("La actividad confirma que ninguna capa es suficiente por sí sola. Las vulnerabilidades más graves (SQLi y "
  "control de acceso roto) nacen en el código y solo el código las corrige; el firewall y el IDS no las "
  "eliminan, pero sí limitan lo que un atacante puede hacer después (DMZ sin camino a la red interna) y "
  "acortan el tiempo de detección (el escaneo previo al ataque quedó registrado y bloqueado en segundos).")
P("Tres aprendizajes concretos: (1) un escáner automático necesita contexto —sin la cookie de sesión ZAP solo "
  "ve la página de login, y sin exclusiones puede borrar la base o cerrar su propia sesión—; (2) en JWT el "
  "error típico no es la criptografía sino la confianza: aceptar el algoritmo que dice el token, o contar el "
  "límite de tasa con un `sub` sin verificar, anula el control; y (3) el mínimo privilegio en red se expresa "
  "como listas de lo permitido, no de lo prohibido: cada zona tiene unas pocas reglas *pass* y un *deny* final con registro.")

H("Referencias")
for ref in [
    "OWASP Foundation. (2021). *OWASP Top 10:2021*. https://owasp.org/Top10/",
    "OWASP Foundation. (2023). *OWASP API Security Top 10 2023*. https://owasp.org/API-Security/",
    "ZAP Dev Team. (2026). *ZAP Automation Framework*. https://www.zaproxy.org/docs/automate/automation-framework/",
    "Hardt, D. (2012). *RFC 6749: The OAuth 2.0 Authorization Framework*. IETF.",
    "Jones, M., Bradley, J. y Sakimura, N. (2015). *RFC 7519: JSON Web Token (JWT)*. IETF.",
    "Sheffer, Y., Hardt, D. y Jones, M. (2020). *RFC 8725: JSON Web Token Best Current Practices*. IETF.",
    "Netgate. (2026). *pfSense Documentation: Firewall Rules, IPsec, pfBlockerNG*. https://docs.netgate.com/pfsense/",
    "Cisco Systems. (2026). *Snort 2.9 Users Manual*. https://www.snort.org/documents",
    "NIST. (2012). *SP 800-30 Rev. 1: Guide for Conducting Risk Assessments*.",
    "NIST. (2020). *SP 800-207: Zero Trust Architecture*.",
]:
    p = doc.add_paragraph()
    add_runs(p, ref.replace("*", "") if False else ref, size=10)
    p.paragraph_format.left_indent = Cm(1)
    p.paragraph_format.first_line_indent = Cm(-1)

# pie de página con número
footer = sec.footer.paragraphs[0]
footer.alignment = WD_ALIGN_PARAGRAPH.CENTER
r = footer.add_run("Act4 · Santiago Gonzalez Ponce · AL03088820 · pág. ")
r.font.size = Pt(8.5)
for kind, text in (("begin", None), (None, "PAGE"), ("end", None)):
    run = footer.add_run()
    run.font.size = Pt(8.5)
    if kind:
        fc = OxmlElement("w:fldChar")
        fc.set(qn("w:fldCharType"), kind)
        run._r.append(fc)
    else:
        it = OxmlElement("w:instrText")
        it.set(qn("xml:space"), "preserve")
        it.text = text
        run._r.append(it)

doc.save(OUT)
print("Generado", OUT)
