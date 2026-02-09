# ADR-015: Interceptor Hooks Architecture

**Status:** 🔒 Planejado (v1.7)
**Crate:** `btv-kernel`

## Decisão
Criar traits `RequestInterceptor` e `ResponseInterceptor` que permitem plugar lógicas customizadas antes e depois do Gatekeeper, seguindo padrão Chain of Responsibility com falha segura (se um hook falhar, a cadeia bloqueia).