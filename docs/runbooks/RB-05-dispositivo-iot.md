# RB-05 · Dispositivo IoT suspeito, clonado ou broker fora

**Alertas:** `TelemetriaSuspeita` (VIN divergente ou odômetro regressivo),
`TelemetriaInvalidaEmMassa` (> 20 mensagens recusadas em 5 min), `IngestorSemBroker`.

## Detecção
- Odômetro voltando = adulteração de quilometragem (fraude de revisão/garantia/revenda).
- VIN do corpo diferente do tópico = device tentando falar em nome de outro carro.
- Muitas recusas de schema = firmware com bug ou device comprometido fazendo fuzzing.
- No broker: `peer did not return a certificate` / `certificate verify failed` = alguém tentando
  conectar sem certificado da CA interna.

## Análise
```logql
{job="ingestor"} | json | event="iot.telemetria_rejeitada" | line_format "{{.vin}} {{.motivo}} {{.detalhe}}"
{job="mosquitto"} |~ "(?i)(certificate|not authori|protocol error)"
```
```sql
select vin, medido_em, odometro_km from telemetria where vin = '<vin>' order by medido_em desc limit 50;
```

## Contenção
1. Revogar o certificado do VIN: incluir na CRL (`crlfile` no `mosquitto.conf`) e reiniciar o broker.
   O certificado de veículo vale só 90 dias, o que limita a janela de um clone.
2. Marcar o VIN para inspeção na próxima visita à concessionária (não gerar lead de revisão
   com km adulterado).
3. Broker fora (`IngestorSemBroker`): ver RB-06; os devices guardam leitura por até 24 h.

## Erradicação
- Reprovisionar o módulo telemático com par de chaves novo (gerado no próprio device).

## Recuperação
- Novo certificado emitido pela CA interna; acompanhar o VIN por 30 dias.

## Pós-incidente
- Se foram vários VINs do mesmo lote, tratar como falha de firmware/fornecedor.
