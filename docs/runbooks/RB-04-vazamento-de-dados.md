# RB-04 · Suspeita de vazamento de dados pessoais

**Alerta:** `ConsultaMassivaDeLeads` (usuário passou de 50 listagens de leads em 1 min).
Também entra aqui qualquer incidente dos outros runbooks que tenha tocado PII.

## Detecção
- Consultor raspando a carteira de clientes (ex.: saindo para concorrente), conta roubada
  ou integração mal-feita.

## Análise
```logql
{job="api", event="audit"} | json | action="MASS_QUERY_DETECTED"
{job="nginx"} | json | uri=~"/v1/leads.*" | line_format "{{.remote_addr}} {{.uri}} {{.status}}"
```
```sql
select actor_id, count(*), min(occurred_at), max(occurred_at)
  from audit_logs where action in ('LEAD_PATCHED','MASS_QUERY_DETECTED')
 group by actor_id order by 2 desc;
```
- Medir o escopo: quais leads/clientes, quais campos. Lembrar que a api só devolve CPF, e-mail e
  telefone **mascarados**; o que sai em claro é nome, modelo do veículo e score.

## Contenção
1. Revogar as sessões da conta (`/revogar-sessoes`) e suspender o usuário.
2. Se o vetor for o banco (dump, backup), rotacionar `FERNET_KEYS` e `CPF_HASH_PEPPER`:
   `python -m app.cli.rotate_keys`.

## Erradicação
- Fechar o vetor (conta, credencial, integração). Revisar permissões com
  `python -m app.cli.auditoria_permissoes`.

## Recuperação e comunicação (LGPD art. 48)
1. Avisar a Ford (controladora) **no mesmo dia** com: natureza dos dados, titulares afetados,
   medidas técnicas (cifra/mascaramento), riscos e medidas tomadas.
2. A Ford decide e comunica ANPD e titulares em até 3 dias úteis se houver risco relevante.
3. Guardar evidências (trilha, logs com `request_id`) por 5 anos junto do relatório.

## Pós-incidente
- Relatório com linha do tempo, escopo, causa raiz e ações; revisar o limiar de 50/min.
