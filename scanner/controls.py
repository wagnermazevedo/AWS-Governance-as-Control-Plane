"""Avaliação dos controles de governança (GOV.1 a GOV.6).

Cada função lê o estado real na AWS e devolve (status, verified_state).
As mesmas funções são usadas pelo scan e pelo remediate, que confere o estado
antes e depois de cada mudança.
"""

from typing import Any, Dict, List, Tuple

from botocore.exceptions import ClientError

from scanner import org as orgapi
from lib.policies import fingerprint, load_policy, same_policy

MANAGED_TAG_KEY = "ManagedBy"
MANAGED_TAG_VALUE = "aws-governance-control-plane"

PASS, FAIL, ERROR, NOT_APPLICABLE = "PASS", "FAIL", "ERROR", "NOT_APPLICABLE"

Result = Tuple[str, Dict[str, Any]]


def check_all_features(org_info: Dict[str, Any]) -> Result:
    feature_set = org_info.get("FeatureSet")
    return (PASS if feature_set == "ALL" else FAIL), {"featureSet": feature_set}


def check_policy_type_enabled(root: Dict[str, Any], policy_type: str) -> Result:
    status = orgapi.policy_type_status(root, policy_type)
    return (PASS if status == "ENABLED" else FAIL), {"policyType": policy_type, "status": status}


def check_policy_attached(org, root: Dict[str, Any], target_id: str, params: Dict[str, Any]) -> Result:
    """O alvo tem a política desejada, com o conteúdo do repositório, direta ou herdada?"""
    policy_type = params["policy_type"]
    name = params["policy_name"]
    desired = load_policy(params["policy_file"], params)
    state: Dict[str, Any] = {
        "policyName": name,
        "policyType": policy_type,
        "policyTypeStatus": orgapi.policy_type_status(root, policy_type),
        "desiredFingerprint": fingerprint(desired),
        "policyId": None,
        "managed": None,
        "contentMatches": None,
        "attachedVia": None,
    }
    if state["policyTypeStatus"] != "ENABLED":
        state["reason"] = "POLICY_TYPE_DISABLED"
        return FAIL, state

    summary = orgapi.find_policy_by_name(org, policy_type, name)
    if not summary:
        state["reason"] = "POLICY_MISSING"
        return FAIL, state

    state["policyId"] = summary["Id"]
    tags = orgapi.tags_for(org, summary["Id"])
    state["managed"] = tags.get(MANAGED_TAG_KEY) == MANAGED_TAG_VALUE
    state["contentMatches"] = same_policy(desired, orgapi.get_policy_content(org, summary["Id"]))

    for node in orgapi.ancestors(org, target_id):
        if summary["Id"] in orgapi.attached_policy_ids(org, node, policy_type):
            state["attachedVia"] = node
            break

    if not state["contentMatches"]:
        state["reason"] = "CONTENT_DRIFT"
        return FAIL, state
    if not state["attachedVia"]:
        state["reason"] = "NOT_ATTACHED"
        return FAIL, state
    state["reason"] = "OK"
    return PASS, state


def expected_state(control: str, params: Dict[str, Any]) -> Dict[str, Any]:
    if control == "GOV.1":
        return {"featureSet": "ALL"}
    if control == "GOV.2":
        return {"policyType": params.get("policy_type"), "status": "ENABLED"}
    if params.get("policy_file"):
        desired = load_policy(params["policy_file"], params)
        return {
            "policyName": params["policy_name"],
            "policyTypeStatus": "ENABLED",
            "contentMatches": True,
            "desiredFingerprint": fingerprint(desired),
            "attached": True,
        }
    if control == "GOV.6":
        return {"parent": "OU"}
    return {}


def _item(control: str, rule: Dict[str, Any], status: str, resource: Dict[str, Any],
          state: Dict[str, Any], detail: str = "") -> Dict[str, Any]:
    return {
        "control": control,
        "title": rule.get("title", control),
        "status": status,
        "resource": resource,
        "verified_state": state,
        "detail": detail,
        "mitre": rule.get("mitre", []) or [],
    }


def _error_detail(err: Exception) -> str:
    if isinstance(err, ClientError):
        return f"{err.response['Error'].get('Code')}: {err.response['Error'].get('Message')}"
    return str(err)


def policy_controls(rules: Dict[str, Any]) -> List[str]:
    """Controles de política por OU: toda regra cuja ação é ensure_policy_attached
    (GOV.3, GOV.4, GOV.5 e qualquer controle novo que você adicionar no mapa)."""
    return sorted(c for c, r in rules.items() if (r or {}).get("action") == "ensure_policy_attached")


def evaluate(org, rules_doc: Dict[str, Any]) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """Avalia todos os controles. Devolve (contexto da organização, itens)."""
    rules = rules_doc.get("rules", {}) or {}
    exc_cfg = rules_doc.get("exception", {}) or {}
    target_names = set((rules_doc.get("targets", {}) or {}).get("ou_names", []) or [])
    policy_ctrls = policy_controls(rules)
    downstream = ["GOV.2", *policy_ctrls, "GOV.6"]
    items: List[Dict[str, Any]] = []
    context: Dict[str, Any] = {"organizationId": None, "managementAccountId": None, "rootId": None}

    # GOV.1: sem organização (ou sem permissão) não há o que governar.
    try:
        org_info = orgapi.describe_organization(org)
    except ClientError as err:
        code = err.response["Error"].get("Code")
        status = FAIL if code == "AWSOrganizationsNotInUseException" else ERROR
        detail = ("Esta conta não pertence a uma organização" if status == FAIL
                  else "Rode a partir da conta de gerenciamento ou de um administrador delegado. " + _error_detail(err))
        items.append(_item("GOV.1", rules.get("GOV.1", {}), status,
                           {"type": "AWS::Organizations::Organization", "id": None}, {"error": code}, detail))
        for control in downstream:
            items.append(_item(control, rules.get(control, {}), NOT_APPLICABLE,
                               {"type": "AWS::Organizations::Organization", "id": None}, {}, "Depende do GOV.1"))
        return context, items

    context["organizationId"] = org_info.get("Id")
    context["managementAccountId"] = org_info.get("MasterAccountId")
    org_resource = {"type": "AWS::Organizations::Organization", "id": org_info.get("Id")}

    status, state = check_all_features(org_info)
    items.append(_item("GOV.1", rules.get("GOV.1", {}), status, org_resource, state))

    try:
        root = orgapi.get_root(org)
    except ClientError as err:
        for control in downstream:
            items.append(_item(control, rules.get(control, {}), ERROR, org_resource, {}, _error_detail(err)))
        return context, items

    context["rootId"] = root["Id"]
    root_resource = {"type": "AWS::Organizations::Root", "id": root["Id"], "name": "Root", "path": "Root"}

    rule = rules.get("GOV.2", {})
    status, state = check_policy_type_enabled(root, (rule.get("params") or {}).get("policy_type", "SERVICE_CONTROL_POLICY"))
    items.append(_item("GOV.2", rule, status, root_resource, state))

    # Controles de política (GOV.3 em diante): avaliados em cada OU alvo do mapa de regras.
    ous = [ou for ou in orgapi.list_ous_recursive(org, root["Id"]) if ou["Name"] in target_names]
    missing = sorted(target_names - {ou["Name"] for ou in ous})
    for control in policy_ctrls:
        rule = rules.get(control, {})
        params = rule.get("params") or {}
        for ou in ous:
            resource = {"type": "AWS::Organizations::OrganizationalUnit", "id": ou["Id"],
                        "name": ou["Name"], "path": ou["Path"]}
            try:
                status, state = check_policy_attached(org, root, ou["Id"], params)
                item = _item(control, rule, status, resource, state)
                tags = orgapi.tags_for(org, ou["Id"])
                if exc_cfg.get("tag_key") in tags:
                    item["exception"] = {
                        "justification": tags.get(exc_cfg["tag_key"]),
                        "owner": tags.get(exc_cfg.get("owner_tag_key", "exception-owner")),
                    }
            except ClientError as err:
                item = _item(control, rule, ERROR, resource, {}, _error_detail(err))
            items.append(item)
    for name in missing:
        items.append(_item("GOV.3", rules.get("GOV.3", {}), NOT_APPLICABLE,
                           {"type": "AWS::Organizations::OrganizationalUnit", "id": None, "name": name},
                           {}, f"OU alvo '{name}' não existe. Suba o lab_insecure ou ajuste targets.ou_names"))

    # GOV.6: contas-membro penduradas direto na raiz.
    rule = rules.get("GOV.6", {})
    try:
        loose = [a for a in orgapi.accounts_under(org, root["Id"]) if a["Id"] != context["managementAccountId"]]
        if not loose:
            items.append(_item("GOV.6", rule, PASS, root_resource, {"accountsUnderRoot": 0}))
        for account in loose:
            items.append(_item("GOV.6", rule, FAIL,
                               {"type": "AWS::Organizations::Account", "id": account["Id"], "name": account.get("Name")},
                               {"parent": root["Id"]}))
    except ClientError as err:
        items.append(_item("GOV.6", rule, ERROR, root_resource, {}, _error_detail(err)))

    return context, items
