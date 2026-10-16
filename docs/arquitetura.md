# Arquitetura

```text
 99_governance_lab_setup.py ──► OUs SCP-Lab e SCP-Lab-Exception, sem nenhuma política
                                        │
                                        ▼
 00_governance_scan.py ── Organizations (Describe/List) ──► scanner/org.py      (leitura da organização)
                                                     └──► scanner/controls.py (GOV.1 a GOV.8, drift)
                                        │
                     outputs/<ts>/governance_scan_export.yaml
                                        │
 01_governance_plan.py ── config/governance_rules.yaml ──► AUTO / MANUAL / EXCEPTION / NO_ACTION
                                        │                   (GOV.2 primeiro)
                              remediation_plan.yaml
                                        │
 02_governance_remediate.py
   ├─ confere o estado ao vivo (o plano pode estar velho)
   ├─ GOV.2: remediate/enable_policy_type.py
   ├─ GOV.3 a GOV.5: remediate/ensure_policy_attached.py (cria, restaura drift, anexa na OU)
   └─ confere de novo (VERIFIED)
                                        │
                     outputs/<ts>/governance_remediation_results.{json,csv} + summary.md
```

## Decisões de projeto

- **O repositório é a fonte da verdade:** o conteúdo esperado de cada política está em `policies/`. Mesmo nome com conteúdo diferente é `CONTENT_DRIFT`, e o apply restaura.
- **Herança conta:** o scan sobe da OU até a raiz, porque uma política anexada acima também protege a OU.
- **Dono explícito:** o remediate só cria ou altera políticas com a tag `ManagedBy=aws-governance-control-plane`. Política com o mesmo nome e outro dono vira MANUAL.
- **Escopo fechado:** só anexa nas OUs de `targets.ou_names`, nunca na raiz nem direto em conta.
- **Saída de emergência:** as SCPs isentam roles `breakglass-*`.
- **Limites da API:** o conteúdo é minificado e validado contra o limite de 5120 caracteres de SCP antes do envio.
- **Destroy conservador:** o lab nunca desabilita tipos de política, porque desabilitar SCP desanexa todas as SCPs da organização.
- **Permission sets fora do escopo:** os permission sets do IAM Identity Center ficam abaixo do teto das SCPs, mas este módulo não os cria nem altera. Eles são auditados no episódio 5, IAM & Identity.
