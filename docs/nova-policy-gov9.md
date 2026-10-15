# Como adicionar uma policy nova: GOV.9 (RCP)

O GOV.9 é uma Resource Control Policy (RCP) que só deixa identidades da sua organização acessarem os buckets S3 das contas governadas. A SCP define o teto do que as **suas identidades** podem fazer; a RCP define o teto do que **qualquer um** pode fazer com os **seus recursos**, inclusive quem está fora da organização.

A boa notícia: para políticas, não precisa escrever código. Toda regra com `action: ensure_policy_attached` já é avaliada pelo scan e aplicada pelo remediate.

Todos os caminhos abaixo são relativos a `~/AWS-Governance-as-Control-Plane`.

---

## Passo 1: escreva a política

O repositório traz um modelo pronto em `policies/examples/rcp-gov-s3-org-only.json`. Copie para `policies/`:

```bash
cd ~
cp ~/AWS-Governance-as-Control-Plane/policies/examples/rcp-gov-s3-org-only.json ~/AWS-Governance-as-Control-Plane/policies/
```

Troque o `o-exemplo` pelo ID da sua organização:

```bash
cd ~
aws organizations describe-organization --query Organization.Id --output text
```

O que a política faz: nega `s3:*` para qualquer principal fora da organização (`aws:PrincipalOrgID`). Os serviços da própria AWS ficam de fora (`aws:PrincipalIsAWSService`), para não quebrar logs do CloudTrail, replicação e afins.

## Passo 2: declare no mapa

Em `config/governance_rules.yaml`, adicione no fim de `rules:`:

```yaml
  GOV.9:
    title: "RCP: S3 só para identidades da organização"
    decision: AUTO
    action: ensure_policy_attached
    params:
      policy_type: RESOURCE_CONTROL_POLICY
      policy_name: rcp-gov-s3-org-only
      policy_file: policies/rcp-gov-s3-org-only.json
      enable_type_if_needed: true
    mitre:
      - T1530      # Data from Cloud Storage
```

- `enable_type_if_needed: true` habilita o tipo RCP na raiz, se ainda estiver desligado.
- Prefere revisar à mão antes? Use `decision: MANUAL` com um `reason`.

## Passo 3: entenda as travas (já vêm de graça)

A ação `ensure_policy_attached` aplica as mesmas travas das outras políticas:

1. **Só as OUs alvo:** apenas as OUs listadas em `targets.ou_names`.
2. **Drift:** se alguém editar a política no console, o scan mostra `CONTENT_DRIFT` e o apply restaura o texto do repo.
3. **Dono:** a política nasce com a tag `ManagedBy`. Se já existir outra com o mesmo nome e sem essa tag, nada é sobrescrito e o item vai para revisão manual.
4. **Exceção:** uma OU com a tag `scp-exception` e um `exception-owner` vira EXCEPTION no plano.
5. **Limites:** no máximo 5120 caracteres e 5 RCPs anexadas diretamente por OU.

## Passo 4: teste

1. Em `tests/test_control_plane.py`, adicione o arquivo em `test_policies_fit_size_limits`:
   ```python
   ("policies/rcp-gov-s3-org-only.json", "RESOURCE_CONTROL_POLICY"),
   ```
2. Rode os testes. O teste `NewPolicyControl` usa o modelo de `policies/examples/` e mostra o GOV.9 indo de FAIL para PASS sem nenhuma linha de código nova:
   ```bash
   cd ~
   python3 -m unittest discover -s ~/AWS-Governance-as-Control-Plane/tests -v
   ```

## Passo 5: rode o ciclo

```bash
cd ~
python3 ~/AWS-Governance-as-Control-Plane/scripts/00_governance_scan.py --region us-east-1
python3 ~/AWS-Governance-as-Control-Plane/scripts/01_governance_plan.py
python3 ~/AWS-Governance-as-Control-Plane/scripts/02_governance_remediate.py --region us-east-1 --mode dry-run
python3 ~/AWS-Governance-as-Control-Plane/scripts/02_governance_remediate.py --region us-east-1 --mode apply
```

No scan, o GOV.9 aparece como FAIL na SCP-Lab. O dry-run mostra que criaria e anexaria a RCP. O apply cria, anexa e termina com VERIFIED.

## Passo 6: comprove que funciona

Na conta de testes dentro da SCP-Lab, deixe um bucket com uma bucket policy pública (só no laboratório!). Tente ler um objeto de fora da organização, por exemplo com `curl` na URL do objeto: o resultado é **AccessDenied**, mesmo com a bucket policy liberando. É o teto da RCP funcionando.

## Passo 7: limpe o laboratório

```bash
cd ~
python3 ~/AWS-Governance-as-Control-Plane/scripts/99_governance_lab_setup.py --destroy
```

O `--destroy` desanexa e apaga as políticas com a tag `ManagedBy` que estejam só no laboratório, incluindo a RCP. Ele não desabilita o tipo RCP na raiz.

> Atenção: RCP vale para todos os buckets das contas da OU. Em produção, comece com uma OU de testes, confira quem acessa os buckets de fora (CloudTrail e IAM Access Analyzer) e só depois amplie.

---

## E se o controle não for "anexar uma política"?

Por exemplo, checar um administrador delegado. Aí sim tem código: a verificação vai em `scanner/controls.py` e, se for AUTO, uma ação nova em `remediate/`, registrada no `remediate/__init__.py`. Os GOV.7 e GOV.8 são bons modelos.
