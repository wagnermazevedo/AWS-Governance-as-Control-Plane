# Controles

| Controle | Verifica | Decisão | Ação | Observação |
|---|---|---|---|---|
| GOV.1 | Organização com *all features* | MANUAL | — | Exige aceite de cada conta-membro |
| GOV.2 | SCPs habilitadas na raiz | AUTO | `enable_policy_type` | Pré-requisito do GOV.3 e GOV.4 |
| GOV.3 | `scp-gov-baseline` na OU | AUTO | `ensure_policy_attached` | Não sair da org, proteger CloudTrail, Config, GuardDuty, Security Hub e Access Analyzer, bloquear root |
| GOV.4 | `scp-gov-region-guardrail` na OU | AUTO | `ensure_policy_attached` | Padrão `us-east-1` e `sa-east-1`; serviços globais isentos |
| GOV.5 | `tag-gov-required-tags` na OU | AUTO | `ensure_policy_attached` | Habilita TAG_POLICY se preciso; padroniza `Environment`, `Owner`, `CostCenter` |
| GOV.6 | Contas-membro direto na raiz | MANUAL | — | Mover conta muda as políticas herdadas |

Status do scan: `PASS`, `FAIL` (com motivo, por exemplo `POLICY_MISSING`, `NOT_ATTACHED` ou `CONTENT_DRIFT`), `NOT_APPLICABLE` e `ERROR`.

Lembrete: SCP não se aplica à conta de gerenciamento. Para ver o efeito, mova uma conta-membro de testes para a `SCP-Lab` com `99_governance_lab_setup.py --move-account`.
