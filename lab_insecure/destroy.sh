#!/bin/bash
# Atalho para desfazer o laboratório.
DIR="$(cd "$(dirname "$0")/.." && pwd)"
python3 "$DIR/scripts/99_governance_lab_setup.py" --destroy "$@"
