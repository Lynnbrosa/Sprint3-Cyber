# RB-07 · Drift ou envenenamento do classificador D0

**Alerta:** `DriftNoPerfilPrevisto` (fatia de "abandono" > 40% na última hora, baseline ~15%).

## Por que é assunto de segurança
O classificador decide quais clientes viram lead e com qual prioridade. Entrada manipulada
(cadastros em massa com o mesmo padrão pelo webhook) ou modelo trocado muda a fila de todas as
concessionárias sem ninguém perceber — é integridade (Tampering no STRIDE).

## Análise
- Grafana › Operação › "Perfis previstos (1h)" e "Distribuição do score de risco".
- A origem dos cadastros do período é legítima? (SIGNATURE_REJECTED junto → RB-03).
- O artefato do modelo em produção é o mesmo que o pipeline publicou? (hash do `ml_model.pkl`
  registrado no build do ml-api; carregar pickle de fonte não confiável é execução de código).

## Contenção
1. Congelar a geração automática de leads críticos (priorização manual) até entender a causa.
2. Voltar para a versão anterior do modelo, se a troca foi o gatilho.

## Erradicação e recuperação
- Remover os cadastros forjados, re-treinar se o dado de treino foi contaminado, recalibrar o baseline.

## Pós-incidente
- Revisar o limiar; registrar a nova distribuição esperada depois de mudança legítima de mercado.
