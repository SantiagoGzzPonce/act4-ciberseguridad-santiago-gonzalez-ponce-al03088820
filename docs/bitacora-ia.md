# Bitácora técnica — Escenario de ataque generado con IA

**Estado:** PENDIENTE — falta pegar la respuesta de la IA (ver sección 2).
**Alumno:** Santiago Gonzalez Ponce — AL03088820
**Herramienta de IA:** _(nombre, modo, fecha)_
**Evidencia:** [captura de la conversación](evidencias/ia-conversacion.png)

## 1. Prompt

> Genera un escenario de ataque a una API que use inyección SQL y JWT mal configurado.
> Incluye vector de ataque, impacto y dos recomendaciones de mitigación

## 2. Respuesta de la IA

Completa y sin editar en [`auditoria-ia/respuesta-ia.md`](auditoria-ia/respuesta-ia.md).

## 3. Lo que la IA hizo bien

## 4. Omisiones y errores encontrados

## 5. Cómo se llevó al laboratorio

`lab-api-segura/app_vulnerable.py` reproduce el escenario (SQL concatenado, HS256 con secreto
débil, `alg=none`, sin `exp`/`aud`) y `app.py` aplica las mitigaciones; los ataques y su bloqueo
están en `docs/evidencias/api-ataque-vulnerable-vs-segura.txt`.
