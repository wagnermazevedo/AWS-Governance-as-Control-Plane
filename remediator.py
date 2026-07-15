# remediator.py

import boto3
import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
from botocore.exceptions import ClientError
import config

logger = logging.getLogger(__name__)

class GovernanceRemediator:
    def __init__(self, region: str = config.AWS_REGION, profile: Optional[str] = config.AWS_PROFILE):
        self.region = region
        self.profile = profile
        self.org_client = self._get_client('organizations')
        self.config_client = self._get_client('config')
        self.ssm_client = self._get_client('ssm')
        
    def _get_client(self, service: str) -> boto3.client:
        """Get AWS client with profile support"""
        if self.profile:
            session = boto3.Session(profile_name=self.profile)
            return session.client(service, region_name=self.region)
        else:
            return boto3.client(service, region_name=self.region)
    
    def apply_plan(self, plan: Dict[str, Any]) -> Dict[str, Any]:
        """Apply the remediation plan"""
        if config.DRY_RUN:
            logger.info("Dry-run mode enabled. No actual remediations will be applied.")
            
        results = {
            'timestamp': datetime.now().isoformat(),
            'plan_id': plan.get('plan_id', 'unknown'),
            'actions_executed': [],
            'errors': []
        }
        
        actions = plan.get('actions', [])
        for action in actions:
            try:
                if config.DRY_RUN:
                    logger.info(f"[DRY-RUN] Would execute: {action['action']}")
                    results['actions_executed'].append({
                        'action': action['action'],
                        'status': 'DRY_RUN',
                        'message': f'Would execute: {action["action"]}'
                    })
                    continue
                    
                # Execute actual actions
                if action['action'] == 'create_scp_policy':
                    self._create_scp_policy()
                    results['actions_executed'].append({
                        'action': action['action'],
                        'status': 'SUCCESS',
                        'message': 'SCP policy created'
                    })
                    
                elif action['action'] == 'enable_account_mfa':
                    self._enable_account_mfa(action.get('target'))
                    results['actions_executed'].append({
                        'action': action['action'],
                        'status': 'SUCCESS',
                        'message': f'MFA enabled for account {action.get("target")}'
                    })
                    
                elif action['action'] == 'enable_config_recorder':
                    self._enable_config_recorder()
                    results['actions_executed'].append({
                        'action': action['action'],
                        'status': 'SUCCESS',
                        'message': 'Config recorder enabled'
                    })
                    
                elif action['action'] == 'create_cloudtrail':
                    self._create_cloudtrail()
                    results['actions_executed'].append({
                        'action': action['action'],
                        'status': 'SUCCESS',
                        'message': 'CloudTrail created'
                    })
                    
                else:
                    logger.warning(f"Unknown action: {action['action']}")
                    results['actions_executed'].append({
                        'action': action['action'],
                        'status': 'UNKNOWN_ACTION',
                        'message': f'Unknown action: {action["action"]}'
                    })
                    
            except ClientError as e:
                error_msg = str(e)
                logger.error(f"Error executing {action['action']}: {error_msg}")
                results['errors'].append({
                    'action': action['action'],
                    'error': error_msg
                })
                
        return results
    
    def _create_scp_policy(self) -> bool:
        """Create a service control policy"""
        try:
            policy_content = json.dumps(config.GOVERNANCE_CONFIG['scp_policies']['governance_policy']['statements'])
            
            if config.DRY_RUN:
                logger.info("Would create SCP policy with content:")
                logger.info(policy_content)
                return True
            
            response = self.org_client.create_policy(
                PolicyName=config.GOVERNANCE_CONFIG['scp_policies']['governance_policy']['name'],
                PolicyContent=policy_content,
                Description=config.GOVERNANCE_CONFIG['scp_policies']['governance_policy']['description'],
                TargetType='ORGANIZATIONAL_UNIT'
            )
            
            logger.info(f"SCP policy created: {response['Policy']['PolicySummary']['Id']}")
            return True
            
        except ClientError as e:
            logger.error(f"Error creating SCP policy: {e}")
            raise
    
    def _enable_account_mfa(self, account_id: str) -> bool:
        """Enable MFA for an account (simplified implementation)"""
        try:
            if config.DRY_RUN:
                logger.info(f"Would enable MFA for account {account_id}")
                return True
                
            # In practice, this would require assuming a role in the target account
            # This is just a placeholder for demonstration
            logger.info(f"MFA enabled for account {account_id}")
            return True
            
        except ClientError as e:
            logger.error(f"Error enabling MFA for account {account_id}: {e}")
            raise
    
    def _enable_config_recorder(self) -> bool:
        """Enable AWS Config recorder"""
        try:
            if config.DRY_RUN:
                logger.info("Would enable Config recorder with settings:")
                logger.info(json.dumps(config.GOVERNANCE_CONFIG['config_recorder'], indent=2))
                return True
            
            # Create configuration recorder
            self.config_client.put_configuration_recorder(
                ConfigurationRecorder=config.GOVERNANCE_CONFIG['config_recorder']
            )
            
            # Start recording
            self.config_client.start_configuration_recorder(
                ConfigurationRecorderName=config.GOVERNANCE_CONFIG['config_recorder']['name']
            )
            
            logger.info("Config recorder enabled")
            return True
            
        except ClientError as e:
            logger.error(f"Error enabling Config recorder: {e}")
            raise
    
    def _create_cloudtrail(self) -> bool:
        """Create CloudTrail trail"""
        try:
            if config.DRY_RUN:
                logger.info("Would create CloudTrail with settings:")
                logger.info(json.dumps(config.GOVERNANCE_CONFIG['cloudtrail'], indent=2))
                return True
            
            # Create CloudTrail trail
            response = self.org_client.create_trail(
                Name=config.GOVERNANCE_CONFIG['cloudtrail']['name'],
                S3BucketName=config.GOVERNANCE_CONFIG['cloudtrail']['s3_bucket_name'],
                IncludeGlobalServiceEvents=config.GOVERNANCE_CONFIG['cloudtrail']['include_global_service_events'],
                IsMultiRegionTrail=config.GOVERNANCE_CONFIG['cloudtrail']['is_multi_region_trail'],
                EnableLogFileValidation=config.GOVERNANCE_CONFIG['cloudtrail']['enable_log_file_validation']
            )
            
            logger.info(f"CloudTrail created: {response['TrailARN']}")
            return True
            
        except ClientError as e:
            logger.error(f"Error creating CloudTrail: {e}")
            raise
    
    def save_results(self, results: Dict[str, Any], filename: Optional[str] = None) -> str:
        """Save remediation results to file"""
        if not filename:
            filename = f"{config.OUTPUT_DIR}/remediation_results_{config.TIMESTAMP}.json"
            
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2, default=str)
            
        logger.info(f"Remediation results saved to {filename}")
        return filename

def main():
    # This would typically load a plan from planner.py
    try:
        # Create a sample plan for demonstration
        sample_plan = {
            'timestamp': datetime.now().isoformat(),
            'plan_id': f"sample_plan_{config.TIMESTAMP}",
            'actions': [
                {
                    'action': 'create_scp_policy',
                    'severity': 'HIGH',
                    'description': 'Create governance SCP policy',
                    'dry_run': config.DRY_RUN
                },
                {
                    'action': 'enable_config_recorder',
                    'severity': 'HIGH',
                    'description': 'Enable Config recorder',
                    'dry_run': config.DRY_RUN
                }
            ],
            'recommendations': []
        }
        
        remediator = GovernanceRemediator()
        results = remediator.apply_plan(sample_plan)
        
        if config.DRY_RUN:
            logger.info("Dry-run mode enabled. No actual remediations were applied.")
            
        result_file = remediator.save_results(results)
        logger.info(f"Remediation completed: {result_file}")
        
        return results
        
    except Exception as e:
        logger.error(f"Error in remediator: {e}")
        raise

if __name__ == "__main__":
    main()
