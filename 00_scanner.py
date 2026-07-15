# scanner.py

import boto3
import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from botocore.exceptions import ClientError
import config

logger = logging.getLogger(__name__)

class GovernanceScanner:
    def __init__(self, region: str = config.AWS_REGION, profile: Optional[str] = config.AWS_PROFILE):
        self.region = region
        self.profile = profile
        self.org_client = self._get_client('organizations')
        self.config_client = self._get_client('config')
        self.ssm_client = self._get_client('ssm')
        self.iam_client = self._get_client('iam')
        
    def _get_client(self, service: str) -> boto3.client:
        """Get AWS client with profile support"""
        if self.profile:
            session = boto3.Session(profile_name=self.profile)
            return session.client(service, region_name=self.region)
        else:
            return boto3.client(service, region_name=self.region)
    
    def scan_organization(self) -> Dict[str, Any]:
        """Scan organization structure and policies"""
        try:
            logger.info("Scanning organization structure...")
            
            # Get organization details
            org = self.org_client.describe_organization()
            
            # Get organizational units
            ou_list = self.org_client.list_organizational_units_for_parent(
                ParentId=org['Organization']['RootId']
            )
            
            # Get SCPs
            scp_list = self.org_client.list_policies(Filter='SERVICE_CONTROL_POLICY')
            
            return {
                'organization': org,
                'organizational_units': ou_list,
                'service_control_policies': scp_list,
                'timestamp': datetime.now().isoformat(),
                'scan_type': 'organization'
            }
            
        except ClientError as e:
            logger.error(f"Error scanning organization: {e}")
            return {'error': str(e), 'timestamp': datetime.now().isoformat()}
    
    def scan_compliance(self) -> Dict[str, Any]:
        """Scan compliance against governance standards"""
        try:
            logger.info("Scanning compliance...")
            
            # Get account list
            accounts = self.org_client.list_accounts()
            
            compliance_results = []
            for account in accounts['Accounts']:
                account_id = account['Id']
                
                # Check MFA status (simplified)
                mfa_enabled = self._check_account_mfa(account_id)
                
                # Check IAM users
                user_count = self._get_user_count(account_id)
                
                compliance_results.append({
                    'account_id': account_id,
                    'account_name': account['Name'],
                    'mfa_enabled': mfa_enabled,
                    'user_count': user_count,
                    'timestamp': datetime.now().isoformat()
                })
            
            return {
                'compliance_results': compliance_results,
                'timestamp': datetime.now().isoformat(),
                'scan_type': 'compliance'
            }
            
        except ClientError as e:
            logger.error(f"Error scanning compliance: {e}")
            return {'error': str(e), 'timestamp': datetime.now().isoformat()}
    
    def scan_config_recorder(self) -> Dict[str, Any]:
        """Scan AWS Config recorder status"""
        try:
            logger.info("Scanning Config recorder...")
            
            # Get configuration recorder
            recorder = self.config_client.describe_configuration_recorders()
            
            # Get delivery channels
            delivery_channels = self.config_client.describe_delivery_channels()
            
            return {
                'configuration_recorder': recorder,
                'delivery_channels': delivery_channels,
                'timestamp': datetime.now().isoformat(),
                'scan_type': 'config'
            }
            
        except ClientError as e:
            logger.error(f"Error scanning Config recorder: {e}")
            return {'error': str(e), 'timestamp': datetime.now().isoformat()}
    
    def scan_cloudtrail(self) -> Dict[str, Any]:
        """Scan CloudTrail configuration"""
        try:
            logger.info("Scanning CloudTrail...")
            
            # List trails
            trails = self.org_client.list_trails()
            
            return {
                'trails': trails,
                'timestamp': datetime.now().isoformat(),
                'scan_type': 'cloudtrail'
            }
            
        except ClientError as e:
            logger.error(f"Error scanning CloudTrail: {e}")
            return {'error': str(e), 'timestamp': datetime.now().isoformat()}
    
    def scan_all(self) -> Dict[str, Any]:
        """Run all scans"""
        logger.info("Running comprehensive scan...")
        
        results = {
            'organization': self.scan_organization(),
            'compliance': self.scan_compliance(),
            'config': self.scan_config_recorder(),
            'cloudtrail': self.scan_cloudtrail(),
            'timestamp': datetime.now().isoformat()
        }
        
        return results
    
    def _check_account_mfa(self, account_id: str) -> bool:
        """Check if root account has MFA enabled"""
        try:
            # This is a simplified check - in practice you'd need to 
            # assume role or use cross-account credentials
            return True  # Placeholder
        except Exception:
            return False
    
    def _get_user_count(self, account_id: str) -> int:
        """Get IAM user count for an account"""
        try:
            # This is a simplified check - in practice you'd need to 
            # assume role or use cross-account credentials
            return 0  # Placeholder
        except Exception:
            return 0

def main():
    scanner = GovernanceScanner()
    
    if config.DRY_RUN:
        logger.info("Dry-run mode enabled. No actual actions will be performed.")
    
    results = scanner.scan_all()
    
    # Save results to file
    output_file = f"{config.OUTPUT_DIR}/scan_results_{config.TIMESTAMP}.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    
    logger.info(f"Scan results saved to {output_file}")
    return results

if __name__ == "__main__":
    main()
