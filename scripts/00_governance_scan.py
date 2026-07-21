import argparse
import os
import yaml
from datetime import datetime, timezone
import boto3

def get_config_non_compliant_resources(config_client):
    items = []
    paginator = config_client.get_paginator('describe_compliance_by_config_rule')
    
    try:
        for page in paginator.paginate(ComplianceTypes=['NON_COMPLIANT']):
            for rule in page.get('ComplianceByConfigRules', []):
                rule_name = rule.get('ConfigRuleName')
                items.append({
                    "ruleName": rule_name,
                    "complianceType": "NON_COMPLIANT",
                    "resourceType": "AWS::Config::ConfigRule"
                })
    except Exception as e:
        print(f"[WARN] Nenhuma regra não-conforme encontrada ou AWS Config inativo: {e}")
        
    return items

def main():
    parser = argparse.ArgumentParser(description="AWS Governance Scan - Config Rules")
    parser.add_argument("--region", required=True)
    parser.add_argument("--output-dir", default="outputs")
    args = parser.parse_args()

    config_client = boto3.client('config', region_name=args.region)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    
    non_compliant = get_config_non_compliant_resources(config_client)

    export = {
        "apiVersion": "governance.shcp/v1",
        "kind": "GovernanceFindingsExport",
        "metadata": {
            "generatedAt": timestamp,
            "region": args.region,
            "source": "aws:config"
        },
        "spec": {
            "items": []
        }
    }

    for idx, item in enumerate(non_compliant, start=1):
        export["spec"]["items"].append({
            "id": f"gov-item-{idx:06d}",
            "finding": {
                "normalized": {
                    "title": item["ruleName"],
                    "complianceStatus": item["complianceType"],
                    "resourceType": item["resourceType"]
                }
            },
            "decision": {
                "type": "MANUAL",
                "reason": "Default export: no governance action mapped"
            },
            "action": {
                "name": "manual",
                "params": {}
            }
        })

    out_dir = os.path.join(args.output_dir, timestamp)
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "governance_scan_export.yaml")

    with open(out_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(export, f, sort_keys=False)

    print(f"[OK] Governance Scan concluído: {out_path}")
    print(f" - Recursos/Regras Não-Conformes: {len(non_compliant)}")

if __name__ == "__main__":
    main()
