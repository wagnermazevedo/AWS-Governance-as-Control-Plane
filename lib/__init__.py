"""Bibliotecas compartilhadas do AWS Governance as Control Plane."""

import re

API_VERSION = "governance.shcp/v1"

# Modo gravação: nomes do laboratório que continuam legíveis na tela.
# Todo o resto (OUs fora do lab, nomes de contas, IDs, e-mails) vira apelido.
LAB_PREFIXES = ("SCP-Lab", "scp-gov-", "tag-gov-", "rcp-gov-")

# IDs de política criados pelo cliente (p-xxxxxxxx). Os gerenciados pela AWS,
# como p-FullAWSAccess, têm maiúsculas e não casam: continuam legíveis.
_POLICY_ID = re.compile(r"\bp-[a-z0-9]{8,128}\b")
_ORG_RESOURCE_TYPES = ("AWS::Organizations::OrganizationalUnit", "AWS::Organizations::Account")


def learn_policy_ids(*texts) -> None:
    """Ensina ao modo gravação os IDs de política que aparecem nesses textos."""
    from lib import mask
    for text in texts:
        mask.learn(_POLICY_ID.findall(str(text or "")), kind="res:p")


def learn_from_items(items) -> None:
    """Ensina ao modo gravação os nomes de OUs e contas e os IDs de política dos itens."""
    from lib import mask
    names = set()
    for item in items or []:
        resource = item.get("resource") or {}
        if resource.get("type") in _ORG_RESOURCE_TYPES:
            names.add(resource.get("name"))
            names.update((resource.get("path") or "").split("/"))
        learn_policy_ids((item.get("verified_state") or {}).get("policyId"), item.get("detail"))
    names.discard("Root")
    # Nomes muito curtos trocariam pedaços de qualquer palavra na tela.
    mask.learn(sorted(n for n in names if n and len(n) >= 3), kind="name")
