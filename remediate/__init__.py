"""Ações de remediação: uma função pequena por tipo de correção.

Toda ação recebe (org, item, params, sim, dry_run) e devolve um dict com
ok, message e changes. Em dry-run nenhuma API de escrita é chamada; o dict
`sim` guarda o que "teria sido feito" para as ações seguintes da mesma execução.
"""

from remediate.enable_policy_type import run as enable_policy_type
from remediate.ensure_policy_attached import run as ensure_policy_attached

REGISTRY = {
    "enable_policy_type": enable_policy_type,
    "ensure_policy_attached": ensure_policy_attached,
}
