# RB-02 · Sessão comprometida e escalação de privilégio

**Alertas:** `ReusoDeRefreshToken` (crítico), `TentativasDeEscalacaoDePrivilegio`
(> 5 FORBIDDEN_ACCESS em 5 min), `TokensInvalidosEmMassa`.

## Detecção
- Reuso de refresh token significa que duas partes têm o mesmo token: o dono e quem roubou
  (malware no celular do consultor, log vazado, proxy). A api **já revogou a família inteira**
  e mandou o webhook `refresh_reuse` para o alert-sink.

## Análise
```logql
{job="api", event="audit"} | json | action=~"REFRESH_REUSE_DETECTED|FORBIDDEN_ACCESS|SESSIONS_REVOKED"
```
```sql
select action, remote_ip, user_agent, occurred_at from audit_logs
 where actor_id = '<usuario>' and occurred_at > now() - interval '24 hours' order by occurred_at;
```
- IP/User-Agent do reuso diferente do uso normal do consultor → roubo confirmado.
- FORBIDDEN_ACCESS em sequência nas rotas `/v1/admin/*` → alguém testando o RBAC com uma conta
  de consultor: tratar como conta comprometida.

## Contenção
1. `POST /v1/admin/usuarios/{id}/revogar-sessoes` (invalida refresh e todo access emitido antes).
2. Trocar a senha; se for app mobile, pedir ao consultor para reinstalar e revisar o aparelho.
3. Se o vetor for vazamento de log/token em outro sistema, isolar esse sistema.

## Erradicação
- Achar a origem do token (dispositivo, extensão, proxy) e remover.
- Se houve acesso a leads, abrir **RB-04** (dado pessoal).

## Recuperação
- Usuário faz login de novo; acompanhar a conta por 7 dias no dashboard SOC.

## Pós-incidente
- Linha do tempo com os `request_id`; avaliar reduzir TTL do refresh ou exigir MFA.
