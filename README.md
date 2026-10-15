# AWS Governance as Control Plane

<p align="center">
  <a href="#-português">Português</a> •
  <a href="#-english">English</a>
</p>

---

## 🇧🇷 Português

O Security Hub mostra o que já está errado. Governança é impedir antes: **guardrails que valem para a organização inteira**, declarados em código e versionados no repositório. Este módulo trata o AWS Organizations, as Service Control Policies (SCPs) e as tag policies como um plano de controle, com o mesmo contrato `scan → plan → remediate` de toda a série.

> **Importante:** este repositório nasce do template [AWS Security Control Plane Scripts](https://github.com/wagnermazevedo/AWS-Security-Control-Plane-Scripts) e segue o mesmo contrato de execução, a mesma estratégia de saídas e o mesmo `test-control-plane.sh`.
>
> ⚠️ **Use somente numa organização de testes.** Este módulo cria e anexa SCPs. Uma SCP mal escrita pode bloquear contas inteiras.

### Objetivos do Módulo

- **Governança como código:** as políticas moram em `policies/`, e o repositório é a fonte da verdade, não o console.
- **Teto de permissões para a organização:** a SCP não concede permissão, ela define o limite. Vale até para o usuário root das contas-membro, mas não para a conta de gerenciamento.
- **Detecção de drift:** se alguém editar uma política no console, o scan percebe.
- **Exceções com dono**, no mesmo padrão `scp-exception` do módulo de Security Hub.

### Controles cobertos

| Controle | O que verifica | Decisão | MITRE ATT&CK |
|---|---|---|---|
| **GOV.1** | A organização usa *all features* (sem isso não existem SCPs) | MANUAL | — |
| **GOV.2** | SCPs habilitadas na raiz | AUTO | — |
| **GOV.3** | SCP `scp-gov-baseline` na OU: não sair da organização, não desligar CloudTrail, Config, GuardDuty, Security Hub e Access Analyzer, bloquear o root das contas-membro | AUTO | T1666, T1562.008, T1078.004 |
| **GOV.4** | SCP `scp-gov-region-guardrail` na OU: só regiões permitidas (padrão `us-east-1` e `sa-east-1`) | AUTO | T1535 |
| **GOV.5** | Tag policy `tag-gov-required-tags` na OU: padroniza `Environment`, `Owner` e `CostCenter` | AUTO | — |
| **GOV.6** | Contas-membro diretamente na raiz, fora de uma OU | MANUAL | — |

GOV.1 e GOV.6 ficam manuais de propósito: migrar para *all features* exige o aceite de cada conta-membro, e mover conta de OU muda as políticas herdadas. Isso é decisão de arquitetura, não de script.

### Contrato de Execução (Scan / Plan / Remediate)

1. **Scan (somente leitura):** avalia cada controle nas OUs listadas em `targets.ou_names`. Sobe a árvore até a raiz (uma política anexada acima também vale) e compara o conteúdo com o arquivo de `policies/`: mesmo nome com conteúdo diferente vira `CONTENT_DRIFT`.
2. **Plan (não muta):** cruza cada item com o `config/governance_rules.yaml` e decide `AUTO`, `MANUAL`, `EXCEPTION` ou `NO_ACTION`. Coloca o GOV.2 primeiro, porque não dá para anexar SCP antes de habilitar SCP.
3. **Remediate (muta, controlado):** dry-run é o padrão. No apply, confere o estado ao vivo, habilita o tipo de política, cria ou restaura a política e anexa na OU, e confere de novo no fim (`VERIFIED`).

> **Regra de Ouro:** nenhuma remediação acontece acidentalmente. Em dry-run, nenhuma API de escrita é chamada.

Guardrails do próprio remediate:
- só anexa em OUs de `targets.ou_names`, nunca na raiz nem direto em conta;
- só cria ou altera políticas com a tag `ManagedBy=aws-governance-control-plane`; se já existir uma política com o mesmo nome de outro dono, o item vira MANUAL;
- uma OU com a tag `scp-exception` vira `EXCEPTION`, com justificativa e dono (`exception-owner`); exceção sem dono volta para MANUAL;
- as SCPs isentam roles `breakglass-*`, para existir uma saída de emergência auditável;
- as políticas são validadas contra o limite de tamanho do AWS Organizations antes de serem enviadas.

### Verificação Automatizada e Testes

O `test-control-plane.sh` do template orquestra os estágios `scripts/00`, `01` e `02`, e o setup `scripts/99` cria o estado inseguro que eles testam:

1. **Provisionamento do estado inseguro:** `scripts/99_governance_lab_setup.py`
2. **Validação da detecção:** `scripts/00_governance_scan.py`
3. **Avaliação da estratégia:** `scripts/01_governance_plan.py`
4. **Aplicação e validação da remediação:** `scripts/02_governance_remediate.py` em dry-run e depois em apply, seguido de um novo scan

Os testes offline (`python3 -m unittest discover -s tests -v`) usam uma organização em memória e validam cada chamada contra o modelo oficial da API do botocore. Eles cobrem que o scan é somente leitura, que o dry-run não escreve nada, as decisões do plano, as exceções sem dono, o apply seguido de um novo scan conforme, a detecção e restauração de drift, a recusa em alterar política de outro dono e o setup e destroy do laboratório.

### Implantação e Replicação via AWS CloudShell

Rode na conta de **gerenciamento** de uma organização de testes (ou num administrador delegado do AWS Organizations).

#### Passo 1: Clonar e instalar

```bash
cd ~
git clone https://github.com/wagnermazevedo/AWS-Governance-as-Control-Plane.git
cd AWS-Governance-as-Control-Plane
pip3 install --user -r requirements.txt
```

#### Passo 2: Criar o laboratório

```bash
python3 scripts/99_governance_lab_setup.py
# opcional: mover uma conta-membro DE TESTES para a OU SCP-Lab, para ver as SCPs em ação
python3 scripts/99_governance_lab_setup.py --move-account <ID-da-conta-de-testes>
```

Cria as OUs `SCP-Lab` (governada) e `SCP-Lab-Exception` (com exceção e dono), sem nenhuma política anexada.

#### Passo 3: Scan, Plan e Remediate

```bash
python3 scripts/00_governance_scan.py --region us-east-1
python3 scripts/01_governance_plan.py \
  --input-yaml outputs/<timestamp>/governance_scan_export.yaml \
  --rules config/governance_rules.yaml \
  --output-yaml outputs/remediation_plan.yaml
python3 scripts/02_governance_remediate.py --region us-east-1 --yaml outputs/remediation_plan.yaml --mode dry-run
python3 scripts/02_governance_remediate.py --region us-east-1 --yaml outputs/remediation_plan.yaml --mode apply
```

Ou pelo orquestrador do template, a partir do `$HOME`:

```bash
~/AWS-Governance-as-Control-Plane/test-control-plane.sh AWS-Governance-as-Control-Plane dry-run
```

Com uma conta-membro na `SCP-Lab`, tente `aws cloudtrail stop-logging --name <trail>` nela: a resposta é `AccessDenied`, mesmo com AdministratorAccess.

#### Passo 4: Simular drift

```bash
python3 scripts/99_governance_lab_setup.py --simulate-drift   # tira a proteção do CloudTrail da SCP baseline
python3 scripts/00_governance_scan.py --region us-east-1      # GOV.3 volta como CONTENT_DRIFT
```

#### Passo 5: Limpar

```bash
python3 scripts/99_governance_lab_setup.py --destroy
```

Devolve a conta movida para a raiz, desanexa e apaga só as políticas deste módulo que não estejam anexadas fora do laboratório e remove as OUs. Os tipos de política continuam habilitados: desabilitar SCP desanexa todas as SCPs da organização.

### Estratégia de Saídas (Outputs)

Cada execução cria uma pasta nova em `outputs/<timestamp>/`, nunca sobrescrita:

- **YAML** (`governance_scan_export.yaml`): entrada do plan.
- **JSON:** fonte da verdade.
- **CSV:** pronto para o Amazon Athena.
- **Markdown** (`summary.md`): resumo para triagem.

O remediate grava JSON, CSV e Markdown, com cada chamada de API feita (`changes`), e não YAML, para que o `test-control-plane.sh` continue encontrando o YAML de scan mais recente.

### Permissões

- **Scan:** `organizations:Describe*`, `organizations:List*`, `sts:GetCallerIdentity`
- **Apply:** também `organizations:EnablePolicyType`, `CreatePolicy`, `UpdatePolicy`, `AttachPolicy` e `TagResource`
- **Laboratório:** `cloudformation:*` na stack do lab, `organizations:CreateOrganizationalUnit`, `DeleteOrganizationalUnit`, `MoveAccount`, `DetachPolicy`, `DeletePolicy`

### Estrutura do Repositório

```text
AWS-Governance-as-Control-Plane/
├── test-control-plane.sh          # Motor de orquestração de testes do template
├── scripts/                       # Estágios que o orquestrador executa
│   ├── 00_governance_scan.py
│   ├── 01_governance_plan.py
│   ├── 02_governance_remediate.py
│   └── 99_governance_lab_setup.py    # Cria, simula drift e desfaz o laboratório
├── config/governance_rules.yaml   # O cérebro: controle -> AUTO / MANUAL / EXCEPTION
├── policies/                      # SCPs e tag policy versionadas (fonte da verdade)
├── scanner/                       # Detecção (somente leitura): leitura da organização e controles
├── remediate/                     # Uma função pequena por tipo de correção
├── lab_insecure/                  # CloudFormation das OUs de laboratório (+ atalhos)
├── tests/                         # Testes offline
├── lib/                           # Clientes AWS, gravadores de saída e políticas
├── reports/                       # Relatórios consolidados
├── outputs/                       # Saídas versionadas (imutáveis)
└── docs/                          # Documentação
```

### Desafio da semana

Adicione um **GOV.7** com uma **Resource Control Policy (RCP)**, por exemplo negando acesso aos buckets S3 da organização para identidades de fora dela (`aws:PrincipalOrgID`). Ela entra em `policies/`, no `governance_rules.yaml` e ganha um teste em `tests/`.

---

## 🇺🇸 English

Security Hub shows what is already wrong. Governance prevents it: **organization-wide guardrails** declared as code and versioned in the repository. This module treats AWS Organizations, Service Control Policies (SCPs) and tag policies as a control plane, following the same `scan → plan → remediate` contract as the rest of the series.

> **Important:** this repository is created from the [AWS Security Control Plane Scripts](https://github.com/wagnermazevedo/AWS-Security-Control-Plane-Scripts) template.
>
> ⚠️ **Use only in a test organization.** This module creates and attaches SCPs.

### Controls

GOV.1 all features enabled (manual) · GOV.2 SCPs enabled at the root · GOV.3 baseline SCP (no leaving the org, protect security services, deny member-account root) · GOV.4 region guardrail SCP · GOV.5 tagging tag policy · GOV.6 accounts directly under the root (manual).

### Safety rails

Policies are attached only to OUs listed in `targets.ou_names` (never the root); only policies tagged `ManagedBy=aws-governance-control-plane` are created or updated; content drift against `policies/` is detected and restored; OUs tagged `scp-exception` with an owner become `EXCEPTION`; `breakglass-*` roles are exempt; dry-run is the default.

### Quick start (AWS CloudShell, management account of a test organization)

```bash
cd ~ && git clone https://github.com/wagnermazevedo/AWS-Governance-as-Control-Plane.git
cd AWS-Governance-as-Control-Plane && pip3 install --user -r requirements.txt
python3 scripts/99_governance_lab_setup.py                 # lab OUs
~/AWS-Governance-as-Control-Plane/test-control-plane.sh AWS-Governance-as-Control-Plane dry-run
python3 scripts/99_governance_lab_setup.py --destroy       # cleanup
```

### Output Strategy

Every run writes a new `outputs/<timestamp>/` folder that is never overwritten: YAML (plan input), JSON (source of truth), CSV (Athena) and `summary.md`. Offline tests: `python3 -m unittest discover -s tests -v`.

### Repository Structure

Same layout as the template (`scanner/`, `remediate/`, `lab_insecure/`, `reports/`, `outputs/`, `lib/`, `docs/`), plus `scripts/` (the 00/01/02/99 stages the orchestrator runs), `config/` (the rule map), `policies/` (versioned SCPs and tag policy) and `tests/`.
