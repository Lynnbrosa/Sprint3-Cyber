## O que muda

## Checklist de seguranca (STRIDE)

- [ ] Rota nova tem `requires_role(...)` ou esta marcada como publica com motivo
- [ ] Entrada nova validada por schema Pydantic com `extra="forbid"` e limites de tamanho
- [ ] Nenhum PII (CPF, e-mail, telefone, localizacao) em log, resposta ou metrica
- [ ] Evento sensivel novo grava na trilha de auditoria (`AuditService.log_event`)
- [ ] Segredo novo vem de variavel de ambiente/secret manager, nunca do codigo
- [ ] Dependencia nova passou no `pip-audit` e tem licenca permitida
- [ ] Threat model (`docs/SPRINT3-CYBERSECURITY.md`, secao 4) atualizado se abriu vetor novo

| STRIDE | Esta mudanca abre algo? |
|---|---|
| Spoofing | |
| Tampering | |
| Repudiation | |
| Information disclosure | |
| Denial of service | |
| Elevation of privilege | |
