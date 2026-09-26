# PrevioPLS · Cybersecurity · Sprint 3 (DevSecOps)

Challenge FIAP 2026 · Ford — Desafio 02 (VIN Share / retenção pós-venda).

| Integrante | RM |
|---|---|
| Giovanne Charelli Zaniboni Silva | 556223 |
| Gustavo Oliveira de Moura | 555827 |
| Lynn Bueno Rosa | 551102 |

**Entrega:** [`docs/Sprint3-Cybersecurity.pdf`](docs/Sprint3-Cybersecurity.pdf) (Word editável:
[`docs/Sprint3-Cybersecurity.docx`](docs/Sprint3-Cybersecurity.docx); mesmo conteúdo em
[`docs/SPRINT3-CYBERSECURITY.md`](docs/SPRINT3-CYBERSECURITY.md)) — documento único separado
pelas quatro atividades: pipeline DevSecOps, segurança em código e infraestrutura,
observabilidade e resposta a incidentes, compliance e segurança contínua.

## O que tem aqui

Camada de segurança do PrevioPLS, evoluída a partir da API da Sprint 2 (commit base `acead24`):

- **API de segurança** (FastAPI): JWT RS256 com `kid`, rotação e detecção de reuso de refresh,
  denylist e kill switch de sessão; RBAC consultor/analista/admin; HMAC anti-replay nos webhooks
  de faturamento; rate limit por IP real; PII cifrada com rotação de chave (MultiFernet).
- **Telemetria de veículo conectado**: Mosquitto só com mTLS e ACL por VIN, ingestor que valida
  schema, relógio e odômetro, com localização generalizada (LGPD).
- **Infra como código endurecida**: Dockerfile sem root/pip/curl pinado por digest, compose com
  `read_only`/`cap_drop`/redes internas, manifests Kubernetes com PSA restricted e NetworkPolicy.
- **Pipeline DevSecOps** ([`.github/workflows/devsecops.yml`](.github/workflows/devsecops.yml)):
  gitleaks, semgrep (com regras do projeto), bandit, pip-audit, hadolint, trivy (config e imagem),
  SBOM, testes, ZAP + ataques MQTT, publicação assinada com cosign e deploy com aprovação.
- **Observabilidade**: Prometheus (17 alertas), Alertmanager, Loki, Grafana (dashboards SOC e
  Operação) e runbooks de resposta em [`docs/runbooks/`](docs/runbooks/).
- **Rotinas contínuas**: auditoria de permissões, backup cifrado, teste de restauração, Dependabot.

## Rodar

Pré-requisito: Docker com Compose v2 (e Python 3 no host só para o passo 1).

```bash
python scripts/bootstrap_env.py      # gera .env e .secrets/ com segredos aleatorios e mostra as senhas de demo
docker compose up -d --build         # api, banco, nginx, broker, ingestor e observabilidade
```

| Endereço | O quê |
|---|---|
| `https://localhost:8443` | API pela borda TLS (CA de dev no volume `cyber3_certs_nginx`) |
| `https://localhost:8443/docs` | Swagger (só fora de produção) |
| `mqtts://localhost:8883` | broker MQTT (exige certificado de cliente) |
| `http://127.0.0.1:3300` | Grafana — pasta PrevioPLS |
| `http://127.0.0.1:9090` / `:9093` | Prometheus / Alertmanager |

Demonstração dos controles:

```bash
docker compose --profile demo run --rm trafego                                   # uso normal + ataques na API
docker compose --profile demo run --rm simulador --modo normal --n 20            # telemetria legitima
docker compose --profile demo run --rm simulador --modo ca-falsa                 # sem-certificado, texto-claro, topico-alheio, payload-invalido, odometro-regressivo
docker compose exec api python -m app.cli.auditoria_permissoes                   # rotina mensal
BACKUP_PASSPHRASE=... ./scripts/backup.sh && ./scripts/restore_test.sh backups/<arquivo>.dump.enc
```

## Testes

```bash
pip install -r requirements.txt pytest anyio
TEST_DATABASE_URL=postgresql+psycopg://usuario:senha@127.0.0.1:5432/banco_de_teste python -m pytest -q
```

75 testes (unitários + integração contra Postgres). Sem `TEST_DATABASE_URL` acessível, só os
unitários rodam. **O banco de teste é recriado do zero a cada execução**: nunca aponte para um
banco com dados.

## Estrutura

```
app/            api (core, rotas, servicos), iot (ingestor, validacao, simulador), cli, ops
alembic/        migrations 0001-0005
tests/          unitarios + integracao
iot/mosquitto/  configuracao e ACL do broker
nginx/          borda TLS
observability/  prometheus, alertas, alertmanager, loki, promtail, grafana
infra/k8s/      manifests de producao
scripts/        certificados, .env, backup/restore
.github/        pipeline, dependabot, CODEOWNERS, template de PR
docs/           documento da sprint, diagramas, runbooks, evidencias
```

Política de segurança e rotinas: [`SECURITY.md`](SECURITY.md).
