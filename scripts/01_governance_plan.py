import argparse
import os
import yaml
from typing import Any, Dict, List, Tuple


def load_yaml(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def save_yaml(path: str, data: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, sort_keys=False, allow_unicode=True)


def match_rule(title: str, rules: List[Dict[str, Any]]) -> Tuple[str, str, Dict[str, Any], str]:
    """Verifica se o nome da regra do AWS Config casa com alguma regra declarativa."""
    title_lower = title.lower()
    for rule in rules:
        needles = rule.get("match_contains", []) or []
        for needle in needles:
            if needle.lower() in title_lower:
                return (
                    "AUTO",
                    rule.get("action", "manual"),
                    rule.get("params", {}) or {},
                    f"Matched governance rule: {rule.get('name', '<unnamed>')}"
                )
    return "MANUAL", "manual", {}, "No governance rule matched"


def main():
    parser = argparse.ArgumentParser(description="AWS Governance Plan - Promote Items to Decisions")
    parser.add_argument("--input-yaml", required=True, help="YAML gerado pelo 00_governance_scan.py")
    parser.add_argument("--rules", required=True, help="Caminho para o governance_rules.yaml")
    parser.add_argument("--output-yaml", required=True, help="Caminho de saída para o plano gerado")
    args = parser.parse_args()

    doc = load_yaml(args.input_yaml)
    rules_doc = load_yaml(args.rules)
    rules = rules_doc.get("rules", []) or []

    items = (doc.get("spec", {}) or {}).get("items", []) or []
    auto_count = 0
    manual_count = 0

    for item in items:
        finding = item.get("finding", {}) or {}
        norm = finding.get("normalized", {}) or {}
        title = norm.get("title", "")

        decision_type, action_name, action_params, reason = match_rule(title, rules)

        item["decision"] = {
            "type": decision_type,
            "reason": reason
        }
        item["action"] = {
            "name": action_name,
            "params": action_params
        }

        if decision_type == "AUTO":
            auto_count += 1
        else:
            manual_count += 1

    meta = doc.get("metadata", {}) or {}
    meta["plannedBy"] = "01_governance_plan.py"
    meta["planSummary"] = {
        "totalItems": len(items),
        "auto": auto_count,
        "manual": manual_count,
        "rulesFile": args.rules
    }
    doc["metadata"] = meta

    save_yaml(args.output_yaml, doc)

    print(f"[OK] Plano de Governança gerado: {args.output_yaml}")
    print(f" - Total de Itens : {len(items)}")
    print(f" - Promovidos AUTO: {auto_count}")
    print(f" - Retidos MANUAL : {manual_count}")


if __name__ == "__main__":
    main()
