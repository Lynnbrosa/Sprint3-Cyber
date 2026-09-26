# RB-03 · Webhook de faturamento adulterado ou em replay

**Alerta:** `AssinaturaHMACRejeitada` (> 3 SIGNATURE_REJECTED em 5 min).

## Detecção
O `POST /v1/clientes` exige `X-Signature` (HMAC-SHA256 de `timestamp.corpo`) e `X-Timestamp`
na janela de 5 min; a mesma assinatura só vale uma vez (`hmac_nonces`).

## Análise
```logql
{job="api", event="audit"} | json | action="SIGNATURE_REJECTED" | line_format "{{.remote_ip}} {{.details}}"
```
| `details` | Leitura |
|---|---|
| `replay` | alguém capturou e reenviou um cadastro legítimo |
| `assinatura_invalida` | corpo alterado no caminho **ou** segredo desalinhado com o emissor |
| `fora_da_janela` | relógio do emissor errado ou replay antigo |
| `headers_ausentes` | cliente não-oficial chamando a rota |

## Contenção
1. Origem fora da rede do faturamento Ford: bloquear o IP na borda.
2. Suspeita de vazamento do segredo: gerar novo `HMAC_PAYLOAD_SECRET` no cofre, publicar no
   emissor e reiniciar a api (o antigo para de valer na hora).

## Erradicação
- Descobrir onde o segredo vazou (repo, log, máquina do integrador). O gitleaks do pipeline
  cobre o repositório; rodar `gitleaks git` no repo do emissor também.

## Recuperação
- Reprocessar os cadastros legítimos que falharam no período (o emissor reenvia com nova assinatura).

## Pós-incidente
- Avaliar mTLS entre faturamento e api como segunda camada.
