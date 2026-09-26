# RB-06 · Indisponibilidade e degradação

**Alertas:** `ComponenteForaDoAr` (crítico), `TaxaDeErro5xxAlta`, `LatenciaP95Alta`, `InferenciaLenta`.
O Alertmanager inibe os alertas de 5xx/latência quando a causa raiz é o componente fora.

## Análise
```bash
docker compose ps
docker compose logs --tail 200 api
curl -s http://127.0.0.1:9090/api/v1/targets | jq '.data.activeTargets[] | {job: .labels.job, health}'
```
- Grafana › PrevioPLS · Operação: RPS, status HTTP, p95 por rota.
- 5xx sem mudança de código recente + pico de requisições → pode ser DoS; cruzar com RB-01.
- `db_error`/`INTERNAL_ERROR` com `incident=` no log: o id bate com a resposta que o cliente viu.

## Contenção
1. Rollback para a última imagem assinada (`cosign verify` + digest anterior).
2. DoS: baixar os limites do nginx e acionar o WAF/CDN.

## Recuperação
- Banco corrompido: restaurar o backup mais recente (`scripts/restore_test.sh` prova que volta)
  ou PITR do banco gerenciado. **RPO 24 h / RTO 4 h** na demo; em produção PITR de 5 min.

## Pós-incidente
- Causa raiz, tempo até detectar e até recuperar; teste de regressão que reproduza a falha.
