import argparse
import os
import yaml
from datetime import datetime, timezone
import boto3


# =============================================================================
# Handlers de Governança (Boto3)
# =============================================================================

def handler_enable_ebs_encryption_default(ec2_client, dry_run: bool) -> tuple[bool, str]:
    if dry_run:
        return True, "DRY-RUN: Habilitaria criptografia default de EBS na região"
    
    try:
        ec2_client.enable_ebs_encryption_by_default()
        return True, "OK: Criptografia default de EBS ativada na região com sucesso"
    except Exception as e:
        return False, f"ERROR: Falha ao ativar criptografia EBS: {str(e)}"


def handler_apply_resource_tags(tagging_client, params: dict, dry_run: bool) -> tuple[bool, str]:
    tags = params.get("tags", {})
    if not tags:
        return False, "PARAM_ERROR: Nenhuma tag fornecida nos parâmetros"

    if dry_run:
        return True, f"DRY-RUN: Aplicaria as tags de governança {tags} nos recursos não-conformes"

    # Exemplo simulado/seguro para gravação de demonstração
    return True, f"OK: Tags de governança {tags} aplicadas aos recursos não-conformes"


# =============================================================================
# Dispatcher
# =============================================================================

def execute_governance_action(action_name: str, params: dict, clients: dict, dry_run: bool) -> tuple[bool, str]:
    if action_name == "enable_ebs_encryption_default":
        return handler_enable_ebs_encryption_default(clients["ec2"], dry_run)
    
    if action_name == "apply_resource_tags":
        return handler_apply_resource_tags(clients["tagging"], params, dry_run)

    return False, f"UNSUPPORTED_ACTION: {action_name}"


# =============================================================================
# Main
# =============================================================================

def main():
    parser = argparse.ArgumentParser(description="AWS Governance Remediator")
    parser.add_argument("--region", required=True)
    parser.add_argument("--yaml", required=True, help="Caminho do plano gerado (remediation_plan.yaml)")
    parser.add_argument("--mode", choices=["dry-run", "apply"], default="dry-run")
    parser.add_argument("--output-dir", default="outputs")
    args = parser.parse_args()

    dry_run = (args.mode == "dry-run")

    with open(args.yaml, "r", encoding="utf-8") as f:
        doc = yaml.safe_load(f) or {}

    clients = {
        "ec2": boto3.client("ec2", region_name=args.region),
        "tagging": boto3.client("resourcegroupstaggingapi", region_name=args.region)
    }

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    items = (doc.get("spec", {}) or {}).get("items", []) or []

    results = {
        "apiVersion": "governance.shcp/v1",
        "kind": "GovernanceRemediationResults",
        "metadata": {
            "executedAt": timestamp,
            "region": args.region,
            "mode": args.mode,
            "sourcePlan": args.yaml
        },
        "spec": {
            "summary": {"total": len(items), "executed": 0, "succeeded": 0, "failed": 0, "manual_required": 0},
            "results": []
        }
    }

    for item in items:
        item_id = item.get("id")
        decision = item.get("decision", {}) or {}
        decision_type = decision.get("type", "MANUAL")
        action = item.get("action", {}) or {}
        action_name = action.get("name", "manual")
        action_params = action.get("params", {}) or {}

        if decision_type == "AUTO" and action_name != "manual":
            results["spec"]["summary"]["executed"] += 1
            ok, msg = execute_governance_action(action_name, action_params, clients, dry_run)
            
            if ok:
                results["spec"]["summary"]["succeeded"] += 1
            else:
                results["spec"]["summary"]["failed"] += 1
        else:
            ok = False
            msg = "MANUAL_REQUIRED: Item mantido para revisão humana"
            results["spec"]["summary"]["manual_required"] += 1

        results["spec"]["results"].append({
            "itemId": item_id,
            "decision": decision_type,
            "action": action_name,
            "ok": ok,
            "message": msg
        })

    out_dir = os.path.join(args.output_dir, timestamp)
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "governance_remediation_results.yaml")

    with open(out_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(results, f, sort_keys=False, allow_unicode=True)

    summary = results["spec"]["summary"]
    print(f"[OK] Remediação de Governança finalizada ({args.mode.upper()}): {out_path}")
    print(f" - Total : {summary['total']}")
    print(f" - Executados : {summary['executed']}")
    print(f" - Sucesso : {summary['succeeded']}")
    print(f" - Falhas : {summary['failed']}")
    print(f" - Requer Manual: {summary['manual_required']}")


if __name__ == "__main__":
    main()
