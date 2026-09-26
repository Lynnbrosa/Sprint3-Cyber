# Runbooks de resposta a incidente

Todo alerta do Prometheus (`observability/prometheus/alerts.yml`) aponta para um destes
arquivos na anotação `runbook`. Cada um segue as fases do plano de resposta
(NIST SP 800-61): **detecção → análise → contenção → erradicação → recuperação → pós-incidente**.

| Runbook | Alertas que abrem | Severidade típica |
|---|---|---|
| [RB-01 Força bruta / flood](RB-01-forca-bruta.md) | ForcaBrutaLogin, ContaBloqueadaPorLockout, FloodBarradoPeloRateLimit | média/alta |
| [RB-02 Sessão comprometida](RB-02-sessao-comprometida.md) | ReusoDeRefreshToken, TentativasDeEscalacaoDePrivilegio, TokensInvalidosEmMassa | crítica/alta |
| [RB-03 Integração adulterada](RB-03-integracao-adulterada.md) | AssinaturaHMACRejeitada | alta |
| [RB-04 Vazamento de dados pessoais](RB-04-vazamento-de-dados.md) | ConsultaMassivaDeLeads | alta/crítica |
| [RB-05 Dispositivo IoT](RB-05-dispositivo-iot.md) | TelemetriaSuspeita, TelemetriaInvalidaEmMassa, IngestorSemBroker | alta |
| [RB-06 Indisponibilidade](RB-06-indisponibilidade.md) | ComponenteForaDoAr, TaxaDeErro5xxAlta, LatenciaP95Alta, InferenciaLenta | crítica/alta |
| [RB-07 Modelo de ML](RB-07-modelo-ml.md) | DriftNoPerfilPrevisto | média |

## Papéis

| Papel | Quem | Faz |
|---|---|---|
| Plantão (N1) | dev de plantão da semana | reconhece o alerta em até 15 min, abre o ticket, executa contenção do runbook |
| Líder do incidente | responsável de segurança do time | classifica severidade, decide contenção maior, conduz o pós-incidente |
| Encarregado (DPO) | Ford (controladora) | decide comunicação à ANPD e aos titulares quando há dado pessoal envolvido |

## Severidade e prazo

| Severidade | Exemplo | Reconhecer | Conter |
|---|---|---|---|
| crítica | sessão roubada, vazamento de PII, API fora | 15 min | 1 h |
| alta | força bruta ativa, webhook adulterado, device clonado | 30 min | 4 h |
| média | lockout isolado, drift do modelo | 4 h | 1 dia útil |

Incidente com dado pessoal (CPF, contato, localização) segue também a LGPD art. 48:
o operador (nós) avisa a Ford **imediatamente**; a Ford comunica ANPD e titulares em até
**3 dias úteis** quando houver risco ou dano relevante (Resolução CD/ANPD nº 15/2024).

## Ferramentas de contenção já prontas

| Ação | Comando / endpoint |
|---|---|
| Derrubar todas as sessões de uma conta | `POST /v1/admin/usuarios/{id}/revogar-sessoes` (admin) |
| Consultar a trilha | `GET /v1/admin/audit-log?action=...` (admin/analista) ou Grafana > Explore > Loki |
| Rotacionar chave de PII | `FERNET_KEYS="nova,antiga"` + `python -m app.cli.rotate_keys` |
| Rotacionar segredo HMAC do faturamento | trocar `HMAC_PAYLOAD_SECRET` no cofre e no emissor, restart da api |
| Revogar certificado de veículo | tirar o CN da CA / CRL no broker (`crlfile`) e restart do mosquitto |
| Bloquear IP na borda | `deny <ip>;` no `nginx.conf` + `nginx -s reload` (ou WAF) |
