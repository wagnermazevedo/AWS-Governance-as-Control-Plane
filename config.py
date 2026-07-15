# config.py

import os
from datetime import datetime

# AWS Configuration
AWS_REGION = os.getenv('AWS_DEFAULT_REGION', 'us-east-1')
AWS_PROFILE = os.getenv('AWS_PROFILE', None)

# Governance Configuration
GOVERNANCE_CONFIG = {
    'organization_structure': {
        'ou_names': ['Production', 'Staging', 'Development', 'Shared-Services'],
        'root_name': 'Root'
    },
    'scp_policies': {
        'governance_policy': {
            'name': 'GovernancePolicy',
            'description': 'Basic governance policy for AWS organization',
            'statements': [
                {
                    'Sid': 'DenyRootAccountAccess',
                    'Effect': 'Deny',
                    'Action': 'iam:DeleteAccount',
                    'Resource': '*'
                },
                {
                    'Sid': 'AllowOnlySpecificRegions',
                    'Effect': 'Deny',
                    'NotAction': [
                        'ec2:DescribeRegions',
                        'ec2:GetRegionInfo'
                    ],
                    'Resource': '*',
                    'Condition': {
                        'StringNotEquals': {
                            'aws:RequestedRegion': [
                                'us-east-1',
                                'us-west-2'
                            ]
                        }
                    }
                }
            ]
        }
    },
    'config_recorder': {
        'name': 'default-recorder',
        'recording_group': {
            'allSupported': True,
            'includeGlobalResourceTypes': True
        }
    },
    'cloudtrail': {
        'name': 'OrganizationTrail',
        's3_bucket_name': 'my-organization-trails-bucket',
        'include_global_service_events': True,
        'is_multi_region_trail': True,
        'enable_log_file_validation': True
    }
}

# MITRE ATT&CK Mapping for MCP (Multi-Cloud Platform) Attacks
MITRE_ATTACK_MAP = {
    'T1078': {
        'name': 'Valid Accounts',
        'description': 'Use of legitimate credentials to gain access to systems',
        'severity': 'HIGH'
    },
    'T1531': {
        'name': 'Account Access Removal',
        'description': 'Removal of accounts from access control lists',
        'severity': 'MEDIUM'
    },
    'T1046': {
        'name': 'Network Service Scanning',
        'description': 'Scanning for open ports and services on network systems',
        'severity': 'MEDIUM'
    },
    'T1562': {
        'name': 'Impair Defenses',
        'description': 'Disabling or modifying security tools and defenses',
        'severity': 'HIGH'
    },
    'T1070': {
        'name': 'Indicator Removal on Host',
        'description': 'Removing or clearing forensic evidence from compromised systems',
        'severity': 'MEDIUM'
    },
    'T1059': {
        'name': 'Command and Scripting Interpreter',
        'description': 'Use of command-line interpreters for execution',
        'severity': 'HIGH'
    },
    'T1083': {
        'name': 'File and Directory Discovery',
        'description': 'Discovery of files and directories on compromised systems',
        'severity': 'LOW'
    },
    'T1105': {
        'name': 'Remote File Copy',
        'description': 'Copying files from remote systems to local systems',
        'severity': 'MEDIUM'
    },
    'T1486': {
        'name': 'Data Encrypted for Ransom',
        'description': 'Encrypting data for ransom purposes',
        'severity': 'CRITICAL'
    },
    'T1578': {
        'name': 'Modify Cloud Compute Infrastructure',
        'description': 'Modification of cloud compute resources',
        'severity': 'HIGH'
    }
}

# Default thresholds for compliance checks
THRESHOLDS = {
    'user_age_days': 365,
    'password_max_age_days': 90,
    'key_max_age_days': 90,
    'inactive_days': 90,
    'breakglass_pattern': r'^(breakglass|admin)-.*'
}

# Output configuration
OUTPUT_DIR = os.getenv('GOVERNANCE_OUTPUT_DIR', './governance_output')
TIMESTAMP = datetime.now().strftime('%Y%m%d_%H%M%S')

# Dry-run mode
DRY_RUN = os.getenv('DRY_RUN', 'false').lower() == 'true'

# Logging configuration
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
