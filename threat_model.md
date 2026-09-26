# Threat Model — PrevioPLS Security API

Aplicação do framework **STRIDE** (Microsoft) ao sistema:
**S**poofing · **T**ampering · **R**epudiation · **I**nformation disclosure · **D**enial of service · **E**levation of privilege.

Escopo: API FastAPI que processa **CPF, dados de veículo e perfil comportamental**. LGPD aplicável — Ford é controlador, este sistema é **operador** (Art. 5º, VIII).

Stakeholders:
- **Consultor** (concessionária): acessa lista de leads + visão 360 + ações.
- **Admin** (gestor regional): cadastra clientes (POST sensível) + consulta auditoria.
- **Analista** (BI): leitura de dashboards/audit_log; sem acesso a PII em claro.
- **Operador externo** (sistema de faturamento Ford): chama POST /v1/clientes via HMAC.

Arquitetura (camadas atacáveis):

```
Internet → nginx (TLS 1.2+) → FastAPI (Python) → PostgreSQL
                                  │
                                  └─→ Provedor LLM externo (via /v1/llm-assist)
```

---

## 1. Validação de entrada (escopo: payloads e parâmetros)

| # | STRIDE | Ameaça | Mitigação |
|---|--------|--------|-----------|
| V1 | **T** | SQL Injection em filtros de lista (`prioridade`, `status`) | Pydantic + Enum tipados; SQLAlchemy parametriza queries; queries dinâmicas sempre via `select().where(...)` — zero string concatenation. |
| V2 | **T** | XSS armazenado em `observacao` do lead (consultor injeta `<script>`) | Sanitização em `LeadService.atualizar_status` (remove caracteres de controle); front-end deve usar React Native que já escapa por padrão; CSP no nginx bloqueia `<script>` em qualquer página retornada. |
| V3 | **T** | Command injection via campos de texto livre | Nenhum input chega a `subprocess`/`os.system` no código atual. Hard rule: revisão de PR bloqueia introdução. |
| V4 | **D** | Payload flooding (body gigante) | nginx `client_max_body_size 1m` + Pydantic `max_length` em strings + uvicorn limites. |
| V5 | **I** | Stack trace vazando estrutura interna | `register_exception_handlers` em `core/errors.py` retorna JSON `{error:{code,message}}`; nunca expõe `repr(exc)`; incident_id correlaciona com log. |
| V6 | **T** | Mass assignment via JSON com campos extras | Todos os schemas Pydantic usam `extra="forbid"` — atributos não declarados retornam 422. |
| V7 | **T** | Formato inválido (CPF de letras, VIN com I/O/Q) | `field_validator` regex estrito: CPF 11 dígitos, VIN 17 alfanuméricos sem I/O/Q, placa Mercosul. |

---

## 2. Autenticação e autorização

| # | STRIDE | Ameaça | Mitigação |
|---|--------|--------|-----------|
| A1 | **S** | Forjar JWT com chave fraca / algoritmo `none` | RS256 (assimétrico, 2048-bit); biblioteca PyJWT valida algoritmo declarado; chave privada fora do código (filesystem 600 ou KMS). |
| A2 | **S** | Replay de access token roubado | TTL curto (15 min); refresh rotacionado a cada uso (`stored.revoked = True`). |
| A3 | **S** | Replay de refresh token | Cada refresh tem `jti` único persistido em `refresh_tokens`. Refresh usado é revogado; tentar usar 2x → 401. Tabela permite revogação em massa por `usuario_id`. |
| A4 | **S** | Brute-force de senha | bcrypt cost 12 (~250ms por hash); `LockoutService` bloqueia email após 5 falhas em 60s por 15 min; alerta dispara webhook. |
| A5 | **E** | Consultor escalando pra admin via tampering no JWT | Assinatura RS256 invalidada — qualquer mudança em `role` quebra a verificação. |
| A6 | **E** | Token de outro escopo (refresh usado como access) | Claim `type` checada explicitamente em `decode_token(expected_type=...)`. |
| A7 | **R** | Usuário nega ter feito ação crítica | `audit_logs` registra `LOGIN_SUCCESS`, `CLIENTE_CREATED`, `LEAD_PATCHED` com `actor_id`, `jti`, `remote_ip`, `request_id`, `user_agent`. |

---

## 3. Proteção de APIs e canais

| # | STRIDE | Ameaça | Mitigação |
|---|--------|--------|-----------|
| P1 | **I** | Sniffing de credenciais em rede | TLS 1.2+ obrigatório no nginx; HSTS 1 ano + preload (HTTP é redirecionado 301 → HTTPS). |
| P2 | **T** | MITM com cert forjado | HSTS preload trava domínio no browser; em prod, certificate pinning seria adicional (mobile pode pinhar via `expo-secure-store`). |
| P3 | **D** | DoS por flood de requests | Rate limit em DOIS níveis: nginx (`limit_req_zone`) + slowapi no app. Endpoints sensíveis (login, llm-assist) com limites agressivos. |
| P4 | **S** | CSRF a partir de site malicioso | API stateless com JWT em header `Authorization` (não cookie); CORS allow_credentials só pra origens whitelistadas. |
| P5 | **T** | Tampering de body em `POST /v1/clientes` (rota crítica LGPD) | HMAC-SHA256 obrigatório (`X-Signature` + `X-Timestamp`); janela de replay 5 min; `hmac.compare_digest` (constant time). |
| P6 | **I** | Exposição de Swagger/OpenAPI em produção | `docs_url=None` quando `app_env=production`; só dev tem `/docs`. |
| P7 | **D** | Abuso da rota LLM (custo $$$ + prompt injection) | Rate limit 10/min por IP no nginx + slowapi; payload max 4000 chars; só Admin/Analista podem chamar; audit obrigatório de cada chamada. |

---

## 4. Dados e privacidade (LGPD)

| # | STRIDE | Ameaça | Mitigação |
|---|--------|--------|-----------|
| D1 | **I** | Dump do banco vaza CPF de todos os clientes | CPF cifrado com Fernet (AES-128-CBC + HMAC-SHA256). Chave fora do banco (env / KMS). `cpf_hash` separado permite lookup sem decifrar. |
| D2 | **I** | Email/telefone em texto plano | Mesma camada Fernet (`email_encrypted`, `telefone_encrypted`); helper `cliente_to_output` mascara antes de serializar. |
| D3 | **I** | PII em dashboards / datasets de ML | `pseudonymize(id)` produz token irreversível pra dimensão de identidade; analista vê `pseudo_<hash>` mas não o CPF. |
| D4 | **I** | Retenção indefinida (Art. 16 LGPD) | `retention_service.anonymize_expired()` substitui PII por pseudônimo após 5 anos; `anonimizado_em` timestampa o evento; mantém perfil/score pra estatística agregada. |
| D5 | **I** | Vazamento via logs (CPF em `logger.info`) | `pii_masking_processor` do structlog mascara CPF, email, Bearer token, sequências longas de dígitos ANTES da escrita. Defesa final. |
| D6 | **R** | Operador interno copia banco offline | Auditoria de acesso ao banco fica no Postgres (`pg_audit`); mitigação é organizacional, não da app. **Gap conhecido**. |
| D7 | **T** | Adulteração silenciosa de PII no banco | Fernet inclui HMAC: qualquer byte alterado faz `InvalidToken` no decrypt → erro 500 detectável; alerta de integridade. |

---

## 5. Logs e auditoria

| # | STRIDE | Ameaça | Mitigação |
|---|--------|--------|-----------|
| L1 | **R** | Usuário malicioso nega operação | `audit_logs` é append-only via aplicação; cada evento tem `request_id` correlacionável com logs estruturados. |
| L2 | **T** | Operador adulterando `audit_logs` direto no Postgres | Mitigação organizacional + `pg_audit` no banco + RBAC do Postgres (app usa user sem `UPDATE` em `audit_logs` em prod — gap atual: usuário único do app tem CRUD; **a fazer**). |
| L3 | **I** | Logs sensíveis num provedor de logs externo | `pii_masking_processor` aplica antes de qualquer encoder; estrutura JSON segura pra ingest. |
| L4 | **D** | Volume de logs degrada disco/SIEM | Logs vão para stdout (12-factor); coletor externo (Loki/CloudWatch) responsável por rotação e retenção. |
| L5 | **S** | Atacante mascarando origem | `RequestIdMiddleware` registra `client_ip` e `User-Agent`; nginx ainda anexa `X-Forwarded-For` real. |
| L6 | — | Anomalias passam despercebidas | `AlertService`: 5 falhas/1min, consulta massiva (>100 leads/min), alteração de perfil → log WARN + webhook. |

---

## Resumo de gaps assumidos (não bloqueantes, mas devem ir pro roadmap)

| Gap | Por que aceito agora | Quando endereçar |
|-----|----------------------|------------------|
| Rate limit em memória (não distribuído) | Single-replica funciona; nginx tem segunda camada | Antes de subir múltiplas réplicas → Redis backend do slowapi/Bucket4j |
| Banco com um único role da aplicação | DataSeeder e migrations exigem CRUD | Ao subir em prod: roles separados (`app_rw` sem `UPDATE audit_logs`, `app_ro` pra analista) |
| Chave Fernet em filesystem | Aceitável em laboratório/dev | Em prod: AWS KMS / GCP KMS / HashiCorp Vault com rotação |
| Self-signed TLS no nginx | Dev sem domínio público | Let's Encrypt via certbot em staging+prod |
| Webhook de alerta opcional, sem SIEM | Ainda na fase de desenvolvimento | Integrar com Slack/PagerDuty/OpenSearch antes do piloto |
| Sem pinning de certificado no app mobile | Reduz fricção de dev | Antes do go-live público |

---

## Como este modelo é mantido

- Toda nova rota deve adicionar uma linha em algum dos 5 quadros.
- PR template deve ter checklist STRIDE: "Esta mudança expõe novo vetor? Para qual categoria?"
- Revisão trimestral do roadmap de gaps acima.
