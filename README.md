Nomes e RMs,
Giovanne Charelli Zaniboni Silva | 556223 
Leonardo Pasquini Baldaia | 557416 
Gustavo Oliveira de Moura | 555827 
Lynn Bueno Rosa | 551102
# PrevioPLS Security API

Backend Python da plataforma **Ford Predict & Care**, focado nos controles de **Cybersecurity** e **LGPD** exigidos pela challenge FIAP 2026 (disciplina Cybersecurity, 100 pts).

Stack: **FastAPI · SQLAlchemy 2 · Pydantic v2 · PostgreSQL · Alembic · structlog · slowapi · cryptography (Fernet + RS256) · nginx TLS reverso**.

> Ford é o **controlador** dos dados; este sistema atua como **operador** (LGPD Art. 5º, VIII).
> Threat model STRIDE completo em [threat_model.md](threat_model.md).

**Repositórios irmãos da challenge:**
[`challenge-SOA`](https://github.com/Lynnbrosa/challenge-SOA) (backend Java/Spring Boot, mesmo domínio de negócio) ·
[`challenge-Mobile`](https://github.com/Lynnbrosa/challenge-Mobile) (app React Native do consultor) ·
[`challenge-IAML`](https://github.com/Lynnbrosa/challenge-IAML) (notebook IA/ML + gerador de seed)

## Estrutura

```
PrevioPLS-Security/
├── app/
│   ├── main.py                    FastAPI factory + meta endpoints
│   ├── core/
│   │   ├── config.py              Pydantic Settings (env-based)
│   │   ├── security.py            JWT RS256 + bcrypt + RBAC dependency
│   │   ├── crypto.py              Fernet + CPF hash + pseudonimização + masking
│   │   ├── hmac_signing.py        Verificação HMAC em payloads críticos
│   │   ├── logging.py             structlog JSON + PII masking processor
│   │   ├── errors.py              Exception handlers globais (sem stack trace)
│   │   ├── middleware.py          Request ID + Security headers
│   │   └── ratelimit.py           slowapi limiter
│   ├── api/v1/
│   │   ├── auth.py                POST /login /refresh /logout
│   │   ├── clientes.py            POST /clientes (Admin + HMAC obrigatório)
│   │   ├── leads.py               GET list / GET id / PATCH (Consultor+)
│   │   └── audit.py               GET /admin/audit-log (Admin/Analista)
│   ├── services/                  Lógica de negócio + auditoria
│   ├── schemas/                   DTOs Pydantic v2 (extra='forbid')
│   ├── models/                    SQLAlchemy ORM
│   └── db/session.py
├── alembic/                       Migrações
├── nginx/
│   ├── nginx.conf                 TLS 1.2+, HSTS, rate limit, security headers
│   └── certs/                     Gerados por scripts/gen_self_signed_cert.sh
├── scripts/
│   ├── gen_rsa_keys.sh            RSA 2048 para JWT
│   ├── gen_self_signed_cert.sh    TLS dev
│   └── gen_fernet_key.py          Chave Fernet
├── tests/test_security.py         Fernet roundtrip, JWT, HMAC, PII masking
├── threat_model.md                STRIDE em 5 domínios
├── docker-compose.yml             db + api + nginx
├── Dockerfile
├── requirements.txt
├── pyproject.toml
└── .env.example
```

## Controles por domínio (mapeamento da rubrica 100 pts)

### 1. Validação de Entrada (20 pts)

| Item | Onde |
|---|---|
| Pydantic v2 com `extra="forbid"` em todos os DTOs | [`app/schemas/`](app/schemas/) |
| Anti SQLi: SQLAlchemy parametriza, Enum tipado em filtros | [`app/services/lead_service.py`](app/services/lead_service.py) |
| Regex estrito: CPF `^\d{11}$`, VIN `^[A-HJ-NPR-Z0-9]{17}$`, placa Mercosul | [`app/schemas/cliente.py`](app/schemas/cliente.py) |
| Sanitização anti-XSS em campo livre `observacao` | [`app/services/lead_service.py`](app/services/lead_service.py) |
| Limites de tamanho: body 1MB (nginx), strings com `max_length` | `nginx.conf` + Pydantic |
| Handler global JSON sem stack trace | [`app/core/errors.py`](app/core/errors.py) |

### 2. Auth & Authz (20 pts)

| Item | Onde |
|---|---|
| JWT **RS256** assimétrico (chaves em `keys/`) | [`app/core/security.py`](app/core/security.py) |
| Access 15 min + refresh 7 dias com rotação + denylist | [`app/services/auth_service.py`](app/services/auth_service.py) + `refresh_tokens` |
| Claim `type` explícita (access vs refresh) impede troca | `decode_token(expected_type=...)` |
| bcrypt cost 12 | `hash_password` em `security.py` |
| RBAC `Consultor / Admin / Analista` via `Depends(requires_role(Role.ADMIN, ...))` | [`app/core/security.py`](app/core/security.py) |
| Lockout: 5 falhas/60s → 15 min de bloqueio | [`app/services/lockout_service.py`](app/services/lockout_service.py) |

### 3. Proteção de APIs (20 pts)

| Item | Onde |
|---|---|
| HTTPS + HSTS preload (TLS 1.2/1.3, ciphers fortes) | [`nginx/nginx.conf`](nginx/nginx.conf) |
| Rate limit nível nginx + slowapi (defesa em profundidade) | nginx `limit_req_zone` + `app/core/ratelimit.py` |
| 100 req/min global · 5 req/min em /login | `.env` + `nginx.conf` |
| CORS whitelist explícita (origins de prod) | `app/main.py` |
| Headers OWASP baseline (HSTS, CSP, X-Frame, etc) duplicados em nginx + middleware | `nginx.conf` + `app/core/middleware.py` |
| HMAC-SHA256 em `POST /v1/clientes` com `X-Signature` + `X-Timestamp` (janela 5 min) | [`app/core/hmac_signing.py`](app/core/hmac_signing.py) |

### 4. Dados e Privacidade (25 pts)

| Item | Onde |
|---|---|
| CPF cifrado com **Fernet** (não-determinístico) + `cpf_hash` HMAC pra lookup | [`app/core/crypto.py`](app/core/crypto.py) + [`app/models/cliente.py`](app/models/cliente.py) |
| Email + telefone também cifrados (Fernet) | mesmo |
| Mascaramento em DTOs: `mask_cpf`, `mask_email`, `mask_telefone` — plaintext nunca sai por response | `cliente_to_output` |
| Pseudonimização irreversível (`pseudo_<sha256-truncado>`) pra ML e dashboards | `pseudonymize()` |
| Retenção LGPD 5 anos → anonimização irreversível agendada | [`app/services/retention_service.py`](app/services/retention_service.py) |
| PII masking nos logs (CPF, email, Bearer, dígitos longos) | `pii_masking_processor` no structlog |

### 5. Logs e Auditoria (15 pts)

| Item | Onde |
|---|---|
| structlog **JSON** com `request_id` correlacionando todos os logs | [`app/core/logging.py`](app/core/logging.py) + `middleware.py` |
| Tabela `audit_logs` (quem, o quê, quando, IP, UA, request_id, details) | [`app/models/audit_log.py`](app/models/audit_log.py) |
| 13 ações cobertas (LOGIN_SUCCESS/FAILED/LOCKED, CLIENTE_*, LEAD_*, UNAUTHORIZED_ACCESS, FORBIDDEN_ACCESS, SIGNATURE_REJECTED, MASS_QUERY_DETECTED) | [`app/models/audit_log.py`](app/models/audit_log.py) |
| Alertas: 5 falhas login/1min, consulta massiva (>100 leads/min), alteração de perfil | [`app/services/alert_service.py`](app/services/alert_service.py) |
| Webhook opcional pra SIEM/Slack/PagerDuty | `SECURITY_ALERT_WEBHOOK_URL` |
| Endpoint admin pra consulta da trilha | `GET /v1/admin/audit-log` |

## Setup completo

### Pré-requisitos
- Docker + Docker Compose
- (Opcional) Python 3.11+ + pip pra rodar fora de container

### 1. Gerar segredos (uma vez)

```bash
chmod +x scripts/*.sh
./scripts/gen_rsa_keys.sh           # cria keys/jwt_private.pem + keys/jwt_public.pem
./scripts/gen_self_signed_cert.sh   # cria nginx/certs/dev.{crt,key}
python scripts/gen_fernet_key.py    # imprime a FERNET_KEY pra usar no .env
```

### 2. Configurar `.env`

```bash
cp .env.example .env
# Cole a FERNET_KEY gerada. Defina CPF_HASH_PEPPER, HMAC_PAYLOAD_SECRET (32 bytes aleatórios).
# Em prod, NÃO use o template.
```

### 3. Subir stack

```bash
docker-compose up --build
# Em paralelo, no primeiro boot, aplique migrations:
docker-compose exec api alembic upgrade head
```

A API fica em:
- `https://localhost/health` (via nginx, TLS)
- `https://localhost/docs` (Swagger UI — só em dev)

Aceite o warning de cert self-signed.

### 4. Testar end-to-end

```bash
# Sem JWT: 401
curl -k https://localhost/v1/leads

# Login (rate limit 5/min)
curl -k -X POST https://localhost/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"consultor@ford.com","senha":"cons123"}'

# POST /clientes EXIGE HMAC. Exemplo de assinatura em bash:
BODY='{"nome":"Maria","cpf":"12345678900","regiao":"SP","veiculo":{"modelo":"Ranger","versao":"XLT","ano":2026,"vin":"9BFZZZ8F7NB000001","data_compra":"2026-05-13","valor_compra":"250000.00","concessionaria_id":"FORD-SP-001"}}'
TS=$(date +%s)
SIG=$(printf '%s.%s' "$TS" "$BODY" | openssl dgst -sha256 -hmac "$HMAC_PAYLOAD_SECRET" | awk '{print $2}')
curl -k -X POST https://localhost/v1/clientes \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <ACCESS_TOKEN_ADMIN>" \
  -H "X-Timestamp: $TS" \
  -H "X-Signature: $SIG" \
  -d "$BODY"
```

### 5. Anonimização agendada (LGPD retention)

Não é cron automático ainda — rode manualmente ou agende no host:

```bash
docker-compose exec api python -c "from app.db.session import session_scope; from app.services.retention_service import anonymize_expired; \\
    s = next(session_scope().__enter__()); print(anonymize_expired(s))"
```

## Testes

```bash
pip install -r requirements.txt pytest
pytest -v
```

`tests/test_security.py` cobre os blocos puros (sem DB):
- Fernet round-trip
- CPF hash determinístico
- Mascaramento de PII (CPF/email/telefone)
- JWT RS256 sign/verify + rejeição de tipo incorreto + tampering
- HMAC constant-time
- PII masking nos logs

## Comandos úteis

```bash
# Nova migration a partir do diff dos models
docker-compose exec api alembic revision --autogenerate -m "descricao"

# Aplicar
docker-compose exec api alembic upgrade head

# Voltar uma
docker-compose exec api alembic downgrade -1

# Tail de logs estruturados
docker-compose logs -f api | jq

# Trilha de auditoria (eventos de segurança nas últimas 24h)
docker-compose exec db psql -U previopls -c "
  SELECT action, count(*) FROM audit_logs
  WHERE occurred_at > NOW() - INTERVAL '24 hours'
  GROUP BY action ORDER BY count DESC;
"
```

## Quê tá pronto pra produção (e o que não tá)

| Pronto | Falta |
|--------|-------|
| TLS + HSTS + CSP + headers OWASP | Cert válido (Let's Encrypt) |
| JWT RS256 com rotação de refresh + denylist | Chave privada em KMS/HSM (hoje em arquivo) |
| Fernet em CPF/email/telefone | Rotação de chave (Fernet `MultiFernet`) |
| Rate limit em 2 camadas (nginx + slowapi) | Redis backend pra rate limit distribuído |
| Audit log + alertas in-process | Integração com SIEM externo |
| Anonimização irreversível 5 anos | Agendador automático (cron/celery) |
| Logs JSON com masking de PII | Coletor central (Loki/CloudWatch) |
| HMAC obrigatório em rota crítica | Rotação programada da chave HMAC |

Detalhamento completo dos riscos residuais no [threat_model.md](threat_model.md).
