#!/usr/bin/env python3
"""[01] PLAN: cruza cada item do scan com o mapa de regras. Não chama a AWS.

Decisões possíveis por item:
  AUTO       -> o remediate corrige (ação e parâmetros vêm do mapa)
  MANUAL     -> fica para revisão humana, com o motivo
  EXCEPTION  -> OU com tag de exceção e dono definido; não é corrigida
  NO_ACTION  -> item conforme ou não aplicável
"""

import argparse
import os
from typing import Any, Dict, Tuple

import _bootstrap  # noqa: F401

from lib import API_VERSION
from scanner.controls import expected_state
from lib.io import load_yaml, write_yaml


def decide(item: Dict[str, Any], rules: Dict[str, Any], exc_cfg: Dict[str, Any]) -> Tuple[str, str, str, Dict[str, Any]]:
    """Devolve (decisão, motivo, ação, parâmetros)."""
    control = item.get("control")
    status = item.get("status")
    rule = rules.get(control)

    if status in ("PASS", "NOT_APPLICABLE"):
        return "NO_ACTION", f"Status {status}", "none", {}
    if status == "ERROR":
        return "MANUAL", "Scan não conseguiu avaliar o item: " + (item.get("detail") or ""), "manual", {}
    if not rule:
        return "MANUAL", f"Controle {control} não está no mapa de regras", "manual", {}

    exception = item.get("exception")
    if exception:
        if exception.get("owner"):
            return ("EXCEPTION",
                    f"Tag {exc_cfg.get('tag_key')}: {exception.get('justification')} (dono: {exception['owner']})",
                    "none", {})
        return "MANUAL", "Exceção sem dono não vale: adicione a tag " + exc_cfg.get("owner_tag_key", "exception-owner"), "manual", {}

    if rule.get("decision") != "AUTO":
        return "MANUAL", rule.get("reason", "Mapa define tratamento manual"), "manual", {}

    state = item.get("verified_state") or {}
    if state.get("managed") is False:
        return "MANUAL", "Já existe política com esse nome fora do controle deste módulo", "manual", {}

    return "AUTO", f"Regra {control}: {rule.get('title', '')}", rule.get("action", "manual"), rule.get("params") or {}


def main():
    parser = argparse.ArgumentParser(description="AWS Governance Plan (não altera recursos)")
    parser.add_argument("--input-yaml", required=True, help="YAML gerado pelo 00_governance_scan.py")
    parser.add_argument("--rules", required=True, help="Caminho do config/governance_rules.yaml")
    parser.add_argument("--output-yaml", required=True, help="Caminho do plano gerado")
    args = parser.parse_args()

    doc = load_yaml(args.input_yaml)
    if doc.get("kind") != "GovernanceFindingsExport":
        raise SystemExit(f"[ERRO] {args.input_yaml} não é um export de scan (kind={doc.get('kind')})")

    rules_doc = load_yaml(args.rules)
    rules = rules_doc.get("rules", {}) or {}
    exc_cfg = rules_doc.get("exception", {}) or {}

    items = (doc.get("spec") or {}).get("items", []) or []
    counts: Dict[str, int] = {"AUTO": 0, "MANUAL": 0, "EXCEPTION": 0, "NO_ACTION": 0}
    for item in items:
        decision, reason, action, params = decide(item, rules, exc_cfg)
        counts[decision] += 1
        item["decision"] = {"type": decision, "reason": reason}
        item["action"] = {"name": action, "params": params}
        if decision == "AUTO":
            item["expected_state"] = expected_state(item["control"], params)

    # Ordem de execução: GOV.2 (habilitar SCPs) antes das políticas que dependem dele.
    items.sort(key=lambda i: (i.get("decision", {}).get("type") != "AUTO", i.get("control", ""), i.get("id", "")))

    plan = {
        "apiVersion": API_VERSION,
        "kind": "GovernanceRemediationPlan",
        "metadata": {
            **(doc.get("metadata") or {}),
            "plannedBy": "01_governance_plan.py",
            "sourceScan": os.path.abspath(args.input_yaml),
            "rulesFile": args.rules,
            "planSummary": {"totalItems": len(items), **{k.lower(): v for k, v in counts.items()}},
        },
        "spec": {"items": items},
    }
    write_yaml(args.output_yaml, plan)

    print(f"[OK] Plano de Governança gerado: {args.output_yaml}")
    print(f" - Total     : {len(items)}")
    for key in ("AUTO", "MANUAL", "EXCEPTION", "NO_ACTION"):
        print(f" - {key:<10}: {counts[key]}")
    print("\n Preview do impacto (estado atual -> esperado):")
    for item in items:
        decision = item["decision"]["type"]
        if decision == "NO_ACTION":
            continue
        resource = item.get("resource") or {}
        current = (item.get("verified_state") or {}).get("reason") or (item.get("verified_state") or {}).get("status") or item.get("status")
        target = "conforme" if decision == "AUTO" else decision.lower()
        print(f"   {item['control']:<6} {decision:<10} {resource.get('path') or resource.get('name') or resource.get('id') or '-':<28} {current} -> {target}")


if __name__ == "__main__":
    main()
