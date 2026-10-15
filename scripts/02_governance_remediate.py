#!/usr/bin/env python3
"""[02] REMEDIATE: executa os itens AUTO do plano. Dry-run é o padrão.

Cada ação confere o estado ao vivo antes de agir (o plano pode estar velho)
e depois de agir (VERIFIED). Itens MANUAL e EXCEPTION são registrados, nunca tocados.

Saída: <output-dir>/<timestamp>/governance_remediation_results.{json,csv} e summary.md.
(Não grava YAML de propósito: o test-control-plane.sh procura o YAML de scan mais recente.)
"""

import argparse
import os

import _bootstrap  # noqa: F401

from lib import API_VERSION
from remediate import REGISTRY
from lib.aws import client, session
from lib.io import DEFAULT_OUTPUTS, DEFAULT_PLAN, load_yaml, markdown_table, new_run_dir, utc_timestamp, write_csv, write_json, write_text

CSV_FIELDS = ["itemId", "control", "decision", "action", "resource", "ok", "message"]


def main():
    parser = argparse.ArgumentParser(description="AWS Governance Remediate")
    parser.add_argument("--region", required=True)
    parser.add_argument("--profile", default=None)
    parser.add_argument("--yaml", default=DEFAULT_PLAN, help="Plano gerado pelo 01_governance_plan.py. Padrão: outputs/remediation_plan.yaml")
    parser.add_argument("--mode", choices=["dry-run", "apply"], default="dry-run")
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUTS)
    args = parser.parse_args()

    if not os.path.exists(args.yaml):
        raise SystemExit(f"[ERRO] Plano não encontrado: {args.yaml}. Rode o 01 (plan) antes do remediate.")
    plan = load_yaml(args.yaml)
    if plan.get("kind") != "GovernanceRemediationPlan":
        raise SystemExit(f"[ERRO] {args.yaml} não é um plano (kind={plan.get('kind')}). Rode o 01_governance_plan.py")

    dry_run = args.mode == "dry-run"
    org = client(session(args.profile, args.region), "organizations")
    sim = {}  # estado simulado compartilhado entre ações da mesma execução

    items = (plan.get("spec") or {}).get("items", []) or []
    summary = {"total": len(items), "executed": 0, "succeeded": 0, "failed": 0, "manual": 0, "exception": 0, "noAction": 0}
    results = []

    for item in items:
        decision = (item.get("decision") or {}).get("type", "MANUAL")
        action = item.get("action") or {}
        action_name = action.get("name", "manual")
        resource = item.get("resource") or {}
        entry = {"itemId": item.get("id"), "control": item.get("control"), "decision": decision,
                 "action": action_name, "resource": resource.get("path") or resource.get("name") or resource.get("id")}

        if decision == "AUTO":
            handler = REGISTRY.get(action_name)
            summary["executed"] += 1
            if not handler:
                outcome = {"ok": False, "message": f"UNSUPPORTED_ACTION: {action_name}", "changes": []}
            else:
                try:
                    outcome = handler(org, item, action.get("params") or {}, sim, dry_run)
                except Exception as err:  # registra e segue: um item quebrado não para os outros
                    outcome = {"ok": False, "message": f"ERROR: {err}", "changes": []}
            summary["succeeded" if outcome["ok"] else "failed"] += 1
            entry.update(ok=outcome["ok"], message=outcome["message"], changes=outcome.get("changes", []))
        elif decision == "EXCEPTION":
            summary["exception"] += 1
            entry.update(ok=True, message="EXCEPTION: " + (item.get("decision") or {}).get("reason", ""))
        elif decision == "NO_ACTION":
            summary["noAction"] += 1
            entry.update(ok=True, message="NO_ACTION")
        else:
            summary["manual"] += 1
            entry.update(ok=False, message="MANUAL_REQUIRED: " + (item.get("decision") or {}).get("reason", ""))
        results.append(entry)

    timestamp = utc_timestamp()
    out = {
        "apiVersion": API_VERSION,
        "kind": "GovernanceRemediationResults",
        "metadata": {"executedAt": timestamp, "region": args.region, "mode": args.mode, "sourcePlan": os.path.abspath(args.yaml)},
        "spec": {"summary": summary, "results": results},
    }
    out_dir = new_run_dir(args.output_dir, timestamp)
    write_json(os.path.join(out_dir, "governance_remediation_results.json"), out)
    write_csv(os.path.join(out_dir, "governance_remediation_results.csv"), results, CSV_FIELDS)
    visible = [r for r in results if r["decision"] != "NO_ACTION"]
    write_text(os.path.join(out_dir, "summary.md"),
               f"# Governance Remediate · {args.mode.upper()} · {timestamp}\n\n"
               + "\n".join(f"- {k}: {v}" for k, v in summary.items()) + "\n\n"
               + markdown_table(visible, ["control", "decision", "resource", "ok", "message"]))

    print(f"[OK] Remediação de Governança finalizada ({args.mode.upper()}): {out_dir}")
    for key, value in summary.items():
        print(f" - {key:<10}: {value}")
    for r in visible:
        print(f"   {r['control']:<6} {r['decision']:<10} {str(r['resource']):<28} {r['message']}")
    if summary["failed"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
