"""GOV.2 (e dependências): habilita um tipo de política na raiz da organização."""

import time
from typing import Any, Dict

from scanner import org as orgapi


def enable(org, policy_type: str, sim: Dict[str, Any], dry_run: bool, wait_seconds: int = 60) -> Dict[str, Any]:
    root = orgapi.get_root(org)  # sempre o estado ao vivo, nunca o ID do arquivo de scan
    status = orgapi.policy_type_status(root, policy_type)
    if status == "ENABLED" or policy_type in sim.setdefault("enabled_types", set()):
        return {"ok": True, "message": f"NOOP: {policy_type} já habilitado na raiz", "changes": []}

    change = {"api": "EnablePolicyType", "RootId": root["Id"], "PolicyType": policy_type}
    if dry_run:
        sim["enabled_types"].add(policy_type)
        return {"ok": True, "message": f"DRY-RUN: habilitaria {policy_type} na raiz {root['Id']}", "changes": [change]}

    if status != "PENDING_ENABLE":
        org.enable_policy_type(RootId=root["Id"], PolicyType=policy_type)
    deadline = time.time() + wait_seconds
    while time.time() < deadline:
        if orgapi.policy_type_status(orgapi.get_root(org), policy_type) == "ENABLED":
            sim["enabled_types"].add(policy_type)
            return {"ok": True, "message": f"OK: {policy_type} habilitado na raiz {root['Id']}", "changes": [change]}
        time.sleep(3)
    return {"ok": False, "message": f"TIMEOUT: {policy_type} ainda não está ENABLED", "changes": [change]}


def run(org, item: Dict[str, Any], params: Dict[str, Any], sim: Dict[str, Any], dry_run: bool) -> Dict[str, Any]:
    return enable(org, params["policy_type"], sim, dry_run)
