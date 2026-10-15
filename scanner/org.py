"""Leitura do AWS Organizations (somente APIs de leitura).

Tudo aqui é usado pelo scan e pela verificação do remediate. Nenhuma função
deste módulo altera estado.
"""

from typing import Any, Dict, List, Optional


def _paginate(org, operation: str, key: str, **kwargs) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    for page in org.get_paginator(operation).paginate(**kwargs):
        items.extend(page.get(key, []))
    return items


def describe_organization(org) -> Dict[str, Any]:
    return org.describe_organization()["Organization"]


def get_root(org) -> Dict[str, Any]:
    roots = _paginate(org, "list_roots", "Roots")
    if not roots:
        raise RuntimeError("Nenhuma raiz encontrada na organização")
    return roots[0]


def policy_type_status(root: Dict[str, Any], policy_type: str) -> str:
    for entry in root.get("PolicyTypes", []):
        if entry.get("Type") == policy_type:
            return entry.get("Status", "DISABLED")
    return "DISABLED"


def list_ous_recursive(org, root_id: str) -> List[Dict[str, Any]]:
    """Lista todas as OUs da árvore, com o caminho a partir da raiz."""
    result: List[Dict[str, Any]] = []
    queue = [(root_id, "Root")]
    while queue:
        parent_id, parent_path = queue.pop(0)
        for ou in _paginate(org, "list_organizational_units_for_parent", "OrganizationalUnits", ParentId=parent_id):
            path = f"{parent_path}/{ou['Name']}"
            result.append({"Id": ou["Id"], "Name": ou["Name"], "Arn": ou.get("Arn"), "Path": path, "ParentId": parent_id})
            queue.append((ou["Id"], path))
    return result


def ancestors(org, target_id: str) -> List[str]:
    """IDs do alvo até a raiz (inclusive). SCPs são herdadas por toda a cadeia."""
    chain = [target_id]
    current = target_id
    while not current.startswith("r-"):
        parents = _paginate(org, "list_parents", "Parents", ChildId=current)
        if not parents:
            break
        current = parents[0]["Id"]
        chain.append(current)
    return chain


def find_policy_by_name(org, policy_type: str, name: str) -> Optional[Dict[str, Any]]:
    for summary in _paginate(org, "list_policies", "Policies", Filter=policy_type):
        if summary.get("Name") == name:
            return summary
    return None


def get_policy_content(org, policy_id: str) -> str:
    return org.describe_policy(PolicyId=policy_id)["Policy"]["Content"]


def attached_policy_ids(org, target_id: str, policy_type: str) -> List[str]:
    return [p["Id"] for p in _paginate(org, "list_policies_for_target", "Policies", TargetId=target_id, Filter=policy_type)]


def service_access(org) -> List[str]:
    """Serviços com acesso confiável (trusted access) habilitado na organização."""
    return [s["ServicePrincipal"] for s in _paginate(org, "list_aws_service_access_for_organization", "EnabledServicePrincipals")]


def delegated_admins(org, service_principal: str) -> List[Dict[str, Any]]:
    return _paginate(org, "list_delegated_administrators", "DelegatedAdministrators", ServicePrincipal=service_principal)


def tags_for(org, resource_id: str) -> Dict[str, str]:
    tags = _paginate(org, "list_tags_for_resource", "Tags", ResourceId=resource_id)
    return {t["Key"]: t["Value"] for t in tags}


def accounts_under(org, parent_id: str) -> List[Dict[str, Any]]:
    return _paginate(org, "list_accounts_for_parent", "Accounts", ParentId=parent_id)
