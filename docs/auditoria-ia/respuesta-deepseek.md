# Respuesta original de DeepSeek (sin editar)

**Prompt:** Genera un escenario de ataque a una API que use inyección SQL y JWT mal configurado. Incluye vector de ataque, impacto y dos recomendaciones de mitigación

**Modo:** chat web, Smart Search activo (consultó 13 páginas). Las marcas de cita numéricas de la interfaz no se conservan al copiar el texto.

---

## Escenario de ataque: Cadena de explotación SQLi + JWT mal configurado

### 1. Vector de ataque

El ataque se articula en dos fases que se potencian mutuamente. La primera aprovecha una **inyección SQL clásica** en un endpoint de autenticación; la segunda explota una **debilidad en la validación del token JWT** para escalar privilegios de forma persistente.

**Fase 1 — Inyección SQL en el endpoint de login**

Supongamos que la API expone `POST /api/v1/auth/login` y construye la consulta por concatenación de strings (patrón vulnerable documentado en OWASP y en análisis de APIs reales) . El atacante envía el siguiente cuerpo JSON:

```json
{"username": "admin' OR '1'='1' --", "password": "cualquiera"}
```

La consulta resultante en el backend sería:

```sql
SELECT * FROM users WHERE username = 'admin' OR '1'='1' --' AND password = '...'
```

El operador `OR '1'='1'` convierte la condición en siempre verdadera, y el comentario `--` anula la verificación de contraseña. La API devuelve un JWT válido para el primer usuario de la tabla, que en muchos sistemas es precisamente la cuenta administrativa .

**Fase 2 — Forja de JWT por algoritmo "none" o clave débil**

Una vez obtenido un token legítimo (aunque sea de un usuario con privilegios elevados), el atacante decodifica su estructura. Si el backend acepta el algoritmo `none` o utiliza una clave secreta débil (por ejemplo, una contraseña memorizable), puede forjar un token con claims arbitrarios. El vector concreto es modificar el header a `{"alg":"none","typ":"JWT"}`, alterar el payload para incluir `"role":"admin"` y eliminar la firma. Si la librería de validación no rechaza explícitamente `none`, la API acepta el token como válido .

Alternativamente, si la clave HS256 es débil, el atacante puede extraerla mediante un ataque de diccionario offline sobre el token capturado y re-firmar un token con privilegios de administrador .

### 2. Impacto

La combinación de ambas vulnerabilidades produce un **compromiso total del sistema de autenticación y autorización**:

| Dimensión | Impacto concreto |
|---|---|
| Confidencialidad | Exfiltración masiva de datos de usuarios (credenciales, PII, historiales) mediante `UNION SELECT` sobre tablas como `users` o `information_schema` . |
| Integridad | Creación de cuentas fraudulentas, modificación de roles y alteración de registros críticos sin trazabilidad fiable. |
| Disponibilidad | Posibilidad de ejecutar `DROP TABLE` o borrado masivo si el usuario de base de datos tiene privilegios excesivos. |
| Evasión de controles | El JWT forjado permite persistencia incluso después de corregir la inyección SQL, ya que el atacante conserva un token válido con privilegios de admin. |
| Alcance | Si la misma clave JWT se comparte entre microservicios, el token forjado es válido en todo el ecosistema . |

El impacto se clasifica como **crítico** porque la cadena de ataque permite pasar de un acceso no autenticado a control administrativo completo en dos pasos, sin necesidad de credenciales legítimas.

### 3. Recomendaciones de mitigación

**Recomendación 1: Eliminar la concatenación SQL mediante consultas parametrizadas**

La causa raíz de la Fase 1 es el uso de strings dinámicos para construir consultas. La mitigación debe aplicarse en el código:

- Sustituir toda concatenación por **consultas parametrizadas** (PreparedStatement en Java/JDBC, placeholders en ORMs, o parámetros vinculados en el driver de base de datos) .
- Ejemplo correcto en un ORM: `User.findOne({ where: { username: req.body.username, password: hash(req.body.password) } })` en lugar de `sequelize.query("SELECT * FROM Users WHERE username = '" + input + "'")` .
- Complementar con **validación de entrada** (tipo de dato, longitud, caracteres permitidos) y **mínimo privilegio** en la cuenta de base de datos que usa la API: el usuario de conexión no debe tener permisos de `DROP`, `ALTER` ni acceso a `information_schema` en producción .

**Recomendación 2: Endurecer la validación de JWT con algoritmos explícitos y claves robustas**

La causa raíz de la Fase 2 es la confianza implícita en el header del token y el uso de secretos débiles. Las acciones concretas son:

- **Fijar el algoritmo en el servidor**: la función de verificación debe recibir una lista explícita de algoritmos permitidos (por ejemplo, `algorithms: ["RS256"]`) y rechazar `none` de forma explícita . El header del token nunca debe determinar el algoritmo de verificación.
- **Usar claves de alta entropía**: para HS256, la clave debe generarse con un CSPRNG (por ejemplo, `openssl rand -base64 48`) y almacenarse en un gestor de secretos, nunca en código ni en variables de entorno legibles . Para sistemas con múltiples verificadores, preferir RS256/ES256 con rotación periódica de claves.
- **Validar claims críticos**: verificar `exp` (expiración), `iss` (emisor), `aud` (audiencia) y `nbf` en cada petición. Un token firmado correctamente pero con `aud` incorrecta debe rechazarse .
- **Acortar la vida útil del token**: access tokens de 15–60 minutos para aplicaciones web, con refresh tokens revocables .

La combinación de ambas mitigaciones rompe la cadena de ataque: sin SQLi no se obtiene el token inicial, y sin un JWT forjable el impacto de una inyección exitosa queda contenido a los privilegios del usuario comprometido, sin escalada a administrador.
