# Bitácora técnica — Escenario de ataque generado con IA

**Fecha:** 2026-11-18
**Herramienta de IA:** DeepSeek (chat web, Smart Search activo: consultó 13 páginas)
**Evidencia:** [captura de la conversación](evidencias/ia-conversacion.png)
**Alumno:** Santiago Gonzalez Ponce — AL03088820

## 1. Prompt

> Genera un escenario de ataque a una API que use inyección SQL y JWT mal configurado.
> Incluye vector de ataque, impacto y dos recomendaciones de mitigación

## 2. Respuesta de la IA

Completa y sin editar en [`auditoria-ia/respuesta-deepseek.md`](auditoria-ia/respuesta-deepseek.md).

Resumen: cadena de dos fases. (1) SQLi en `POST /api/v1/auth/login` con
`admin' OR '1'='1' --` para saltarse la contraseña y obtener un JWT; (2) forja de un JWT con
`alg=none` o re-firmado tras romper por diccionario una clave HS256 débil, con `"role":"admin"`.
Impacto en tabla CIA + evasión y alcance (clasificado crítico). Mitigaciones: consultas
parametrizadas + validación + mínimo privilegio en BD; y JWT con algoritmo fijo, claves de alta
entropía, validación de `exp/iss/aud/nbf` y tokens de vida corta.

## 3. Lo que la IA hizo bien

- **Cumple el formato pedido:** vector, impacto y exactamente dos recomendaciones, cada una
  atacando la causa raíz de una fase.
- **Las dos fallas de JWT correctas:** `alg=none` y secreto HS256 débil roto offline; e insiste en
  que **el header del token nunca debe elegir el algoritmo** (lista blanca en el servidor).
- **Mitigación de JWT completa:** RS256/ES256 para varios verificadores, claves por CSPRNG,
  validación de `exp`, `iss`, `aud`, `nbf` y vida de 15–60 min.
- **Mínimo privilegio en la BD** como límite del daño (sin `DROP`/`ALTER`), y nota sobre la clave
  compartida entre microservicios, un riesgo real que suele pasarse por alto.

## 4. Omisiones y errores encontrados

| # | Tema | Hallazgo en la respuesta | Corrección |
|---|---|---|---|
| 1 | Ejemplo de ORM "correcto" | `findOne({ where: { username, password: hash(req.body.password) } })` compara un hash determinista en la consulta: implica guardar contraseñas con un hash rápido **sin sal** (MD5/SHA), justo lo que el Paso 1 rompió en DVWA. | Buscar por `username` y verificar con `bcrypt.compare`/Argon2id (hash lento con sal). |
| 2 | Payload SQL dependiente del motor | La consulta resultante queda `'1'='1' --' AND password…`: en MySQL/MariaDB `--` solo es comentario si va seguido de un espacio, así que ese texto da error de sintaxis. Funciona en PostgreSQL, SQLite o SQL Server. | Usar `-- ` (con espacio) o `#` en MySQL; aclarar el motor supuesto. |
| 3 | "Sin acceso a `information_schema`" | En MySQL/MariaDB no se puede revocar: todo usuario ve los metadatos de los objetos sobre los que tiene algún permiso. La recomendación no es aplicable tal cual. | Limitar los objetos con permisos (solo las tablas de la app, `SELECT/INSERT/UPDATE` mínimos) y vistas para lo sensible. |
| 4 | Respuesta al incidente | Dice que el JWT forjado da persistencia "incluso después de corregir la SQLi", pero no propone **rotar la clave de firma** (con `kid`/JWKS) ni revocar tokens emitidos, que es lo único que invalida los tokens ya forjados. | Rotar la llave, revocar por `jti`/lista de denegación y forzar re-login tras el incidente. |
| 5 | Confusión de algoritmos | Recomienda RS256 pero no advierte del ataque RS256→HS256 (firmar con la llave **pública** como secreto HMAC) ni de la inyección por `kid`/`jku`. Su lista blanca lo evita, pero no lo explica. | Lista blanca de un solo algoritmo por llave; ignorar `jku`/`x5u` y validar `kid` contra JWKS local. |
| 6 | Rate limiting y detección | No menciona límite de intentos en `/login` ni registro/alerta de 401 o errores SQL, aunque la actividad pide rate limiting y las sondas de SQLi generan ruido detectable. | 100 sol./min por cliente + bloqueo progresivo en login; WAF/IDS y alertas. |
| 7 | Mensajes de error | No pide errores genéricos: los errores de BD visibles facilitan la SQLi (en la API vulnerable el error devolvía la consulta completa). | Respuestas genéricas y detalle solo en el log del servidor. |
| 8 | Autorización por claim | Trata `"role":"admin"` del token como dato de confianza sin decir que el rol debe salir de una fuente del servidor o de *scopes* emitidos por el servidor de autorización. | Scopes asignados por el emisor y verificación por endpoint (403). |
| 9 | Coherencia de la cadena | Presenta las fases como dependientes ("una vez obtenido un token legítimo…"), pero `alg=none` no necesita ningún token previo: la Fase 2 sola basta para ser admin. | Tratar cada falla como explotable por separado. |
| 10 | Fuentes | Las citas de Smart Search no se conservan al copiar y no permiten verificar qué afirmación respalda cada página. | Contrastar con OWASP API Top 10 2023 y RFC 8725 (JWT BCP). |

## 5. Cómo se llevó al laboratorio

`lab-api-segura/app_vulnerable.py` reproduce el escenario (SQL concatenado, HS256 con el secreto
de diccionario `secret`, `alg=none`, sin `exp`/`aud`, rol tomado del token, errores de BD
visibles) y `app.py` aplica las mitigaciones de la IA **más** las correcciones de la sección 4
(scopes del emisor, rate limiting, errores genéricos, PBKDF2 para secretos de cliente, `kid`/JWKS).
La SQLi del laboratorio está en un parámetro de búsqueda (`UNION SELECT`) en vez del login.
Resultados en `docs/evidencias/api-ataque-vulnerable-vs-segura.txt`: los tres ataques funcionan
contra la versión vulnerable y reciben 401/400 en la segura.
