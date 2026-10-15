#!/bin/bash
# Atalho para o setup do laboratório (scripts/99_governance_lab_setup.py). Organização de testes, sempre.
DIR="$(cd "$(dirname "$0")/.." && pwd)"
python3 "$DIR/scripts/99_governance_lab_setup.py" "$@"
