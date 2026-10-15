"""GOV.3 em diante (toda regra com action ensure_policy_attached): garante que a política do repositório exista, esteja
com o conteúdo versionado e anexada à OU alvo.

Guardrails da própria ação:
- só anexa em OU (ID ou-...), nunca na raiz nem direto em conta;
- só cria ou altera políticas com a tag ManagedBy=aws-governance-control-plane;
- confere o estado depois de aplicar.
"""

from typing import Any, Dict, List

from scanner import org as orgapi
from remediate.enable_policy_type import enable as enable_type
from scanner.controls import MANAGED_TAG_KEY, MANAGED_TAG_VALUE, PASS, check_policy_attached
from lib.policies import MAX_ATTACHED, check_size, compact, load_policy, same_policy


def run(org, item: Dict[str, Any], params: Dict[str, Any], sim: Dict[str, Any], dry_run: bool) -> Dict[str, Any]:
    target_id = (item.get("resource") or {}).get("id") or ""
    if not target_id.startswith("ou-"):
        return {"ok": False, "message": f"REFUSED: alvo '{target_id}' não é uma OU", "changes": []}

    policy_type = params["policy_type"]
    name = params["policy_name"]
    desired = load_policy(params["policy_file"], params)
    check_size(desired, policy_type)
    changes: List[Dict[str, Any]] = []
    notes: List[str] = []

    # 1. O tipo de política precisa estar habilitado na raiz.
    root = orgapi.get_root(org)
    enabled = (orgapi.policy_type_status(root, policy_type) == "ENABLED"
               or policy_type in sim.setdefault("enabled_types", set()))
    if not enabled:
        if not params.get("enable_type_if_needed"):
            return {"ok": False, "changes": [],
                    "message": f"DEPENDENCY: {policy_type} desabilitado na raiz; o GOV.2 precisa ser aplicado antes"}
        result = enable_type(org, policy_type, sim, dry_run)
        changes += result["changes"]
        notes.append(result["message"])
        if not result["ok"]:
            return {"ok": False, "message": " | ".join(notes), "changes": changes}

    # 2. A política existe, é nossa e está com o conteúdo do repositório?
    summary = orgapi.find_policy_by_name(org, policy_type, name)
    policy_id = summary["Id"] if summary else sim.setdefault("created", {}).get(name)
    if summary:
        if orgapi.tags_for(org, policy_id).get(MANAGED_TAG_KEY) != MANAGED_TAG_VALUE:
            return {"ok": False, "changes": changes,
                    "message": f"REFUSED: já existe '{name}' sem a tag {MANAGED_TAG_KEY}={MANAGED_TAG_VALUE}; revise manualmente"}
        if not same_policy(desired, orgapi.get_policy_content(org, policy_id)):
            changes.append({"api": "UpdatePolicy", "PolicyId": policy_id})
            if dry_run:
                notes.append(f"DRY-RUN: restauraria o conteúdo versionado de {name} (drift detectado)")
            else:
                org.update_policy(PolicyId=policy_id, Content=compact(desired))
                notes.append(f"OK: conteúdo de {name} restaurado")
    elif not policy_id:
        changes.append({"api": "CreatePolicy", "Name": name, "Type": policy_type})
        if dry_run:
            policy_id = f"<nova:{name}>"
            notes.append(f"DRY-RUN: criaria a política {name}")
        else:
            created = org.create_policy(
                Name=name,
                Type=policy_type,
                Description=f"Gerenciada pelo AWS Governance as Control Plane ({item.get('control')})",
                Content=compact(desired),
                Tags=[{"Key": MANAGED_TAG_KEY, "Value": MANAGED_TAG_VALUE}],
            )
            policy_id = created["Policy"]["PolicySummary"]["Id"]
            notes.append(f"OK: política {name} criada ({policy_id})")
        sim["created"][name] = policy_id

    # 3. Anexada à OU (direta ou herdada)?
    attached = False
    if not policy_id.startswith("<nova:"):
        for node in orgapi.ancestors(org, target_id):
            if policy_id in orgapi.attached_policy_ids(org, node, policy_type):
                attached = True
                break
    attach_key = (policy_id, target_id)
    if not attached and attach_key not in sim.setdefault("attached", set()):
        # Cota de políticas por OU: com o Control Tower ela enche rápido. Melhor parar com
        # uma mensagem clara do que receber ConstraintViolationException no meio do apply.
        limit = MAX_ATTACHED.get(policy_type)
        direct = len(orgapi.attached_policy_ids(org, target_id, policy_type))
        pending = sum(1 for (pid, tid) in sim["attached"] if tid == target_id and sim.get("types", {}).get(pid) == policy_type)
        if limit and direct + pending >= limit:
            return {"ok": False, "changes": changes,
                    "message": " | ".join(notes + [f"QUOTA: a OU {target_id} já tem {direct + pending} {policy_type} "
                                                   f"anexadas (limite {limit}). Com Control Tower, as SCPs dos controles "
                                                   "dele contam aqui; junte políticas ou anexe numa OU acima"])}
        sim.setdefault("types", {})[policy_id] = policy_type
        changes.append({"api": "AttachPolicy", "PolicyId": policy_id, "TargetId": target_id})
        if dry_run:
            notes.append(f"DRY-RUN: anexaria {name} à OU {target_id}")
        else:
            org.attach_policy(PolicyId=policy_id, TargetId=target_id)
            notes.append(f"OK: {name} anexada à OU {target_id}")
        sim["attached"].add(attach_key)

    if not changes:
        return {"ok": True, "message": f"NOOP: {name} já conforme em {target_id}", "changes": []}
    if dry_run:
        return {"ok": True, "message": " | ".join(notes), "changes": changes}

    # 4. Verificação pós-mudança: corrigir sem conferir é trabalho pela metade.
    status, state = check_policy_attached(org, orgapi.get_root(org), target_id, params)
    if status != PASS:
        return {"ok": False, "changes": changes,
                "message": " | ".join(notes) + f" | VERIFY_FAILED: {state.get('reason')}"}
    return {"ok": True, "message": " | ".join(notes) + " | VERIFIED", "changes": changes}
