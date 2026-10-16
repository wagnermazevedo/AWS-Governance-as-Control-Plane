#!/usr/bin/env python3
"""[00] SCAN: avalia os controles de governança da organização. Somente leitura.

Saída (pasta nova por execução, nunca sobrescrita):
  <output-dir>/<timestamp>/governance_scan_export.yaml  -> entrada do plan
  <output-dir>/<timestamp>/governance_scan_export.json
  <output-dir>/<timestamp>/governance_scan_export.csv   -> Athena
  <output-dir>/<timestamp>/summary.md                   -> gente
"""

import argparse
import os
from collections import Counter

import _bootstrap  # noqa: F401

from lib import API_VERSION, LAB_PREFIXES, learn_from_items, mask
from lib.aws import client, session
from scanner.controls import evaluate
from lib.io import DEFAULT_OUTPUTS, load_yaml, markdown_table, new_run_dir, repo_path, utc_timestamp, write_csv, write_json, write_text, write_yaml

CSV_FIELDS = ["id", "control", "status", "resource_type", "resource_id", "resource_name", "reason", "detail"]


def flatten(item):
    resource = item.get("resource") or {}
    return {
        "id": item["id"],
        "control": item["control"],
        "status": item["status"],
        "resource_type": resource.get("type"),
        "resource_id": resource.get("id"),
        "resource_name": resource.get("path") or resource.get("name"),
        "reason": (item.get("verified_state") or {}).get("reason", ""),
        "detail": item.get("detail", ""),
    }


def main():
    mask.setup(keep_prefixes=LAB_PREFIXES)  # modo gravação: antes do argparse, para aceitar --no-mask
    parser = argparse.ArgumentParser(description="AWS Governance Scan (somente leitura)")
    parser.add_argument("--region", required=True)
    parser.add_argument("--profile", default=None)
    parser.add_argument("--rules", default=repo_path("config", "governance_rules.yaml"))
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUTS, help="Padrão: outputs/ do repositório")
    args = parser.parse_args()

    rules_doc = load_yaml(args.rules)
    sess = session(args.profile, args.region)
    org = client(sess, "organizations")
    caller = client(sess, "sts").get_caller_identity()

    clients = {"config": client(sess, "config"), "controltower": client(sess, "controltower")}
    context, items = evaluate(org, rules_doc, clients)
    learn_from_items(items)  # nomes de OUs fora do lab e de contas viram apelido na tela
    for idx, item in enumerate(items, start=1):
        item["id"] = f"gov-item-{idx:06d}"

    timestamp = utc_timestamp()
    counts = Counter(i["status"] for i in items)
    export = {
        "apiVersion": API_VERSION,
        "kind": "GovernanceFindingsExport",
        "metadata": {
            "generatedAt": timestamp,
            "region": args.region,
            "source": "aws:organizations,aws:config,aws:controltower",
            "callerAccountId": caller.get("Account"),
            "organization": context,
            "rulesFile": os.path.relpath(args.rules, repo_path()),
            "summary": dict(counts),
        },
        "spec": {"items": items},
    }

    out_dir = new_run_dir(args.output_dir, timestamp)
    write_yaml(os.path.join(out_dir, "governance_scan_export.yaml"), export)
    write_json(os.path.join(out_dir, "governance_scan_export.json"), export)
    rows = [flatten(i) for i in items]
    write_csv(os.path.join(out_dir, "governance_scan_export.csv"), rows, CSV_FIELDS)
    write_text(os.path.join(out_dir, "summary.md"),
               f"# Governance Scan · {timestamp}\n\n"
               f"Organização: `{context.get('organizationId')}` · Conta chamadora: `{caller.get('Account')}`\n\n"
               + markdown_table(rows, ["control", "status", "resource_name", "reason", "detail"]))

    print(f"[OK] Governance Scan concluído: {out_dir}/governance_scan_export.yaml")
    for status in ("FAIL", "PASS", "ERROR", "NOT_APPLICABLE"):
        print(f" - {status:<15}: {counts.get(status, 0)}")
    for row in rows:
        if row["status"] != "PASS":
            print(f"   {row['control']:<6} {row['status']:<15} {row['resource_name'] or '-':<28} {row['reason'] or row['detail']}")


if __name__ == "__main__":
    main()
