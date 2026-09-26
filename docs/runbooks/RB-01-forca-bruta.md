# RB-01 · Força bruta, credential stuffing e flood

**Alertas:** `ForcaBrutaLogin` (> 10 LOGIN_FAILED em 5 min), `ContaBloqueadaPorLockout`,
`FloodBarradoPeloRateLimit` (> 50 respostas 429 da api em 5 min).

## Detecção
- Grafana › PrevioPLS · SOC › "Falhas de login (1h)", "Top IPs com falha de login".
- Controles que já agiram sozinhos: rate limit do nginx (5/min no login), slowapi (5/min),
  lockout (5 falhas em 60 s → 15 min).

## Análise
```logql
sum by (remote_ip) (count_over_time({job="api", event="audit"} | json | action="LOGIN_FAILED" [15m]))
{job="api", event="audit"} | json | action=~"LOGIN_FAILED|LOGIN_LOCKED" | line_format "{{.remote_ip}} {{.actor_email}}"
```
- Um IP, muitas contas → *password spraying*. Muitos IPs, uma conta → alvo direcionado.
- Algum `LOGIN_SUCCESS` do mesmo IP logo depois das falhas? Se sim, vira **RB-02**.

## Contenção
1. IP único e externo: `deny <ip>;` no nginx (ou regra no WAF) por 24 h.
2. Houve login com sucesso no meio: `POST /v1/admin/usuarios/{id}/revogar-sessoes` e troca de senha.
3. Ataque distribuído: baixar `RATE_LIMIT_LOGIN` e acionar desafio (CAPTCHA) no front.

## Erradicação
- Senha da conta atacada trocada; revisar se a senha aparece em vazamentos públicos.
- MFA para admin e analista (backlog prioritário se ainda não estiver ativo).

## Recuperação
- Lockout expira sozinho em 15 min; desbloqueio antecipado só depois de falar com o usuário.
- Remover o `deny` depois de 24 h sem novas tentativas.

## Pós-incidente
- Registrar IPs, janela, contas-alvo e se houve acesso. Ajustar limiar do alerta se foi ruído.
