#!/usr/bin/env python3
"""[99] LAB SETUP: cria o ambiente que os scripts 00, 01 e 02 vão testar. Use SOMENTE numa organização de testes.

Rode na conta de GERENCIAMENTO da organização de testes.

  python3 scripts/99_governance_lab_setup.py                              # cria as OUs SCP-Lab e SCP-Lab-Exception
  python3 scripts/99_governance_lab_setup.py --move-account 111122223333  # e move uma conta-membro de testes para a SCP-Lab
  python3 scripts/99_governance_lab_setup.py --simulate-drift             # tira a proteção do CloudTrail da SCP baseline
  python3 scripts/99_governance_lab_setup.py --destroy                    # desfaz tudo

O --destroy devolve a conta movida para a raiz, desanexa e apaga só as políticas com a tag
ManagedBy=aws-governance-control-plane que não estejam anexadas fora do laboratório, e remove as OUs.
Ele não desabilita os tipos de política: desabilitar SCP desanexa TODAS as SCPs da organização.
"""

import argparse
import json
import os

import _bootstrap  # noqa: F401
from botocore.exceptions import ClientError

from lib import LAB_PREFIXES, learn_policy_ids, mask
from lib.aws import client, session
from lib.io import repo_path
from scanner import org as orgapi
from scanner.controls import MANAGED_TAG_KEY, MANAGED_TAG_VALUE

STATE_FILE = repo_path("lab_insecure", ".lab_state.json")
TEMPLATE = repo_path("lab_insecure", "governance-lab.yaml")
POLICY_TYPES = ("SERVICE_CONTROL_POLICY", "RESOURCE_CONTROL_POLICY", "TAG_POLICY")


def _code(err):
    return err.response.get("Error", {}).get("Code", "")


def _load_state():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def _save_state(state):
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)


def stack_outputs(cfn, stack):
    try:
        outputs = cfn.describe_stacks(StackName=stack)["Stacks"][0].get("Outputs", [])
    except ClientError as err:
        if "does not exist" in str(err):
            return {}
        raise
    return {o["OutputKey"]: o["OutputValue"] for o in outputs}


def setup(org, cfn, stack, move_account):
    root_id = orgapi.get_root(org)["Id"]
    with open(TEMPLATE, "r", encoding="utf-8") as f:
        body = f.read()
    try:
        cfn.create_stack(StackName=stack, TemplateBody=body,
                         Parameters=[{"ParameterKey": "RootId", "ParameterValue": root_id}])
        cfn.get_waiter("stack_create_complete").wait(StackName=stack)
        print(f"[OK] Stack {stack} criada")
    except ClientError as err:
        if _code(err) != "AlreadyExistsException":
            raise
        print(f"[OK] Stack {stack} já existia")
    outputs = stack_outputs(cfn, stack)
    for key, value in outputs.items():
        print(f"   {key:<22} {value}")

    if move_account:
        org.move_account(AccountId=move_account, SourceParentId=root_id, DestinationParentId=outputs["ScpLabOUId"])
        state = _load_state()
        state["movedAccount"] = {"accountId": move_account, "originalParent": root_id}
        _save_state(state)
        print(f"[OK] Conta {mask.mask_text(move_account)} movida para a OU SCP-Lab")
    print("[OK] Laboratório pronto. Lembrete: SCP não se aplica à conta de gerenciamento.")


def simulate_drift(org):
    summary = orgapi.find_policy_by_name(org, "SERVICE_CONTROL_POLICY", "scp-gov-baseline")
    if not summary:
        raise SystemExit("scp-gov-baseline não existe ainda. Rode o remediate em modo apply primeiro.")
    learn_policy_ids(summary["Id"])
    doc = json.loads(orgapi.get_policy_content(org, summary["Id"]))
    for stmt in doc.get("Statement", []):
        if stmt.get("Sid") == "ProtectSecurityServices":
            stmt["Action"] = [a for a in stmt["Action"] if not a.startswith("cloudtrail:")]
    org.update_policy(PolicyId=summary["Id"], Content=json.dumps(doc, separators=(",", ":")))
    print(f"[OK] Drift aplicado em {summary['Id']}: o CloudTrail ficou desprotegido. Rode o scan.")


def destroy(org, cfn, stack):
    state = _load_state()
    lab_ous = set(stack_outputs(cfn, stack).values())

    moved = state.get("movedAccount")
    if moved:
        parents = [p["Id"] for p in org.list_parents(ChildId=moved["accountId"])["Parents"]]
        if parents and parents[0] in lab_ous:
            org.move_account(AccountId=moved["accountId"], SourceParentId=parents[0],
                             DestinationParentId=moved["originalParent"])
            print(f"[OK] Conta {mask.mask_text(moved['accountId'])} devolvida para a raiz")

    for policy_type in POLICY_TYPES:
        try:
            policies = org.list_policies(Filter=policy_type)["Policies"]
        except ClientError as err:
            if _code(err) == "PolicyTypeNotEnabledException":
                continue
            raise
        learn_policy_ids(*(p["Id"] for p in policies))
        for policy in policies:
            if orgapi.tags_for(org, policy["Id"]).get(MANAGED_TAG_KEY) != MANAGED_TAG_VALUE:
                continue
            for target in lab_ous:
                try:
                    org.detach_policy(PolicyId=policy["Id"], TargetId=target)
                    print(f"[OK] {policy['Name']} desanexada de {target}")
                except ClientError as err:
                    if _code(err) != "PolicyNotAttachedException":
                        raise
            remaining = org.list_targets_for_policy(PolicyId=policy["Id"])["Targets"]
            if remaining:
                print(f"[WARN] {policy['Name']} mantida: ainda anexada a {len(remaining)} alvo(s) fora do laboratório")
            else:
                org.delete_policy(PolicyId=policy["Id"])
                print(f"[OK] {policy['Name']} apagada")

    if lab_ous:
        cfn.delete_stack(StackName=stack)
        cfn.get_waiter("stack_delete_complete").wait(StackName=stack)
        print(f"[OK] Stack {stack} removida")
    if os.path.exists(STATE_FILE):
        os.remove(STATE_FILE)
    print("Os tipos de política continuam habilitados na raiz (desabilitar SCP desanexa todas as SCPs da organização).")


def main():
    mask.setup(keep_prefixes=LAB_PREFIXES)  # modo gravação: antes do argparse, para aceitar --no-mask
    parser = argparse.ArgumentParser(description="Governance Lab Setup (organização de testes)")
    parser.add_argument("--region", default="us-east-1", help="Região do CloudFormation (use us-east-1)")
    parser.add_argument("--profile", default=None)
    parser.add_argument("--stack-name", default="governance-control-plane-lab")
    parser.add_argument("--move-account", default=None, help="Conta-membro DE TESTES a mover para a SCP-Lab")
    parser.add_argument("--simulate-drift", action="store_true")
    parser.add_argument("--destroy", action="store_true")
    parser.add_argument("--yes", action="store_true", help="Não pede confirmação")
    args = parser.parse_args()

    sess = session(args.profile, args.region)
    org = client(sess, "organizations")
    cfn = client(sess, "cloudformation")

    if args.destroy:
        destroy(org, cfn, args.stack_name)
        return
    if args.simulate_drift:
        simulate_drift(org)
        return

    info = orgapi.describe_organization(org)
    print(f"Organização {mask.mask_text(info['Id'])} · conta de gerenciamento {mask.mask_text(info['MasterAccountId'])}")
    if not args.yes and input("Digite LAB para confirmar que esta é uma organização de testes: ").strip() != "LAB":
        raise SystemExit("Cancelado.")
    setup(org, cfn, args.stack_name, args.move_account)


if __name__ == "__main__":
    main()
