# Politica de seguranca

## Como reportar uma vulnerabilidade

Nao abra issue publica. Use o GitHub Security Advisories deste repositorio
("Security" > "Report a vulnerability") com passos de reproducao e impacto.
Resposta inicial em ate 2 dias uteis; correcao de CVSS >= 7 em ate 7 dias.

## Versoes suportadas

So a branch `main` recebe correcao de seguranca.

## Rotinas

| Rotina | Frequencia | Como |
|---|---|---|
| Revisao de dependencias | semanal (segunda) | Dependabot + job `sca` agendado no pipeline |
| Testes de seguranca | a cada push/PR + semanal | pipeline DevSecOps (SAST, SCA, IaC, imagem, DAST) |
| Auditoria de permissoes | mensal | `python -m app.cli.auditoria_permissoes` |
| Backup | diario | `scripts/backup.sh` (cifrado, sha256, retencao 7 dias) |
| Teste de restauracao | mensal | `scripts/restore_test.sh` |
| Rotacao de chave de PII | semestral ou em incidente | `FERNET_KEYS` + `python -m app.cli.rotate_keys` |
| Revisao do threat model | trimestral | secao 4 do documento da Sprint 3 |

Detalhes em [docs/SPRINT3-CYBERSECURITY.md](docs/SPRINT3-CYBERSECURITY.md).
