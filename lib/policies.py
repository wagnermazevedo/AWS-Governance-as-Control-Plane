"""Carga, renderização e comparação de políticas da organização (SCP e tag policy)."""

import copy
import hashlib
import json
from typing import Any, Dict, Optional

from lib.io import repo_path

# Limites de tamanho do AWS Organizations (caracteres do documento enviado).
SIZE_LIMITS = {
    "SERVICE_CONTROL_POLICY": 5120,
    "TAG_POLICY": 10000,
}


def load_policy(policy_file: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Lê a política do repositório e aplica os parâmetros do mapa de regras."""
    with open(repo_path(policy_file), "r", encoding="utf-8") as f:
        doc = json.load(f)
    params = params or {}
    regions = params.get("allowed_regions")
    if regions:
        doc = copy.deepcopy(doc)
        for stmt in doc.get("Statement", []):
            cond = stmt.get("Condition", {}).get("StringNotEquals", {})
            if "aws:RequestedRegion" in cond:
                cond["aws:RequestedRegion"] = list(regions)
    return doc


def compact(doc: Dict[str, Any]) -> str:
    """Serialização compacta: é o que vai para a API e o que conta para o limite."""
    return json.dumps(doc, separators=(",", ":"), sort_keys=True)


def fingerprint(doc: Dict[str, Any]) -> str:
    return hashlib.sha256(compact(doc).encode("utf-8")).hexdigest()[:16]


def parse_content(content: str) -> Dict[str, Any]:
    return json.loads(content) if content else {}


def same_policy(desired: Dict[str, Any], current_content: str) -> bool:
    """Compara ignorando espaços e ordem de chaves; listas de ações são comparadas como conjuntos."""
    return _normalize(desired) == _normalize(parse_content(current_content))


def check_size(doc: Dict[str, Any], policy_type: str) -> None:
    limit = SIZE_LIMITS.get(policy_type)
    size = len(compact(doc))
    if limit and size > limit:
        raise ValueError(f"Política com {size} caracteres excede o limite de {limit} para {policy_type}")


def _normalize(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _normalize(v) for k, v in value.items()}
    if isinstance(value, list):
        items = [_normalize(v) for v in value]
        if all(isinstance(v, str) for v in items):
            return sorted(set(items))
        return items
    return value
