# __init__.py

"""
AWS Governance Control Plane - Multi-Script Architecture

This package provides a modular approach to AWS governance with:
- Scan functionality for identifying issues
- Plan generation for remediation actions
- Remediation execution with dry-run capability
- MITRE ATT&CK mapping for MCP (Multi-Cloud Platform) attacks

Usage:
    python cli.py scan
    python cli.py plan --scan-results scan_results.json
    python cli.py remediate --plan-file remediation_plan.json
"""

__version__ = "1.0.0"
__author__ = "AWS Governance Team"
