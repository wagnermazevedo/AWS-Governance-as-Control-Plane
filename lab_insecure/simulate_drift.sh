#!/bin/bash
# Atalho: tira a proteção do CloudTrail da SCP baseline. O próximo scan deve acusar CONTENT_DRIFT no GOV.3.
DIR="$(cd "$(dirname "$0")/.." && pwd)"
python3 "$DIR/scripts/99_governance_lab_setup.py" --simulate-drift "$@"
