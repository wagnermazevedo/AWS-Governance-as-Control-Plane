# planner.py

import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
import config

logger = logging.getLogger(__name__)

class GovernancePlanner:
    def __init__(self):
        self.scan_results = None
        self.plan = {}
        
    def load_scan_results(self, scan_results: Dict[str, Any]):
        """Load scan results for planning"""
        self.scan_results = scan_results
        
    def generate_plan(self) -> Dict[str, Any]:
        """Generate remediation plan based on scan results"""
        if not self.scan_results:
            raise ValueError("No scan results loaded. Please load scan results first.")
            
        logger.info("Generating remediation plan...")
        
        plan = {
            'timestamp': datetime.now().isoformat(),
            'plan_id': f"plan_{config.TIMESTAMP}",
            'actions': [],
            'recommendations': []
        }
        
        # Analyze organization structure
        org_results = self.scan_results.get('organization', {})
        if 'error' not in org_results:
            plan['actions'].extend(self._analyze_organization(org_results))
            
        # Analyze compliance
        compliance_results = self.scan_results.get('compliance', {})
        if 'error' not in compliance_results:
            plan['actions'].extend(self._analyze_compliance(compliance_results))
            
        # Analyze config recorder
        config_results = self.scan_results.get('config', {})
        if 'error' not in config_results:
            plan['actions'].extend(self._analyze_config(config_results))
            
        # Analyze CloudTrail
        cloudtrail_results = self.scan_results.get('cloudtrail', {})
        if 'error' not in cloudtrail_results:
            plan['actions'].extend(self._analyze_cloudtrail(cloudtrail_results))
        
        # Add recommendations
        plan['recommendations'] = self._generate_recommendations()
        
        self.plan = plan
        return plan
    
    def _analyze_organization(self, org_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze organization structure for improvements"""
        actions = []
        
        # Check if SCPs are properly configured
        scp_policies = org_results.get('service_control_policies', {}).get('Policies', [])
        if not scp_policies:
            actions.append({
                'action': 'create_scp_policy',
                'severity': 'HIGH',
                'description': 'No service control policies found in organization',
                'dry_run': config.DRY_RUN
            })
            
        return actions
    
    def _analyze_compliance(self, compliance_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze compliance for improvements"""
        actions = []
        
        # Check if accounts have MFA enabled
        results = compliance_results.get('compliance_results', [])
        for account in results:
            if not account.get('mfa_enabled'):
                actions.append({
                    'action': 'enable_account_mfa',
                    'severity': 'CRITICAL',
                    'description': f'Account {account["account_id"]} does not have MFA enabled',
                    'target': account['account_id'],
                    'dry_run': config.DRY_RUN
                })
                
        return actions
    
    def _analyze_config(self, config_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze Config recorder configuration"""
        actions = []
        
        # Check if Config is enabled
        recorder = config_results.get('configuration_recorder', {})
        if not recorder:
            actions.append({
                'action': 'enable_config_recorder',
                'severity': 'HIGH',
                'description': 'AWS Config recorder not found or not enabled',
                'dry_run': config.DRY_RUN
            })
            
        return actions
    
    def _analyze_cloudtrail(self, cloudtrail_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze CloudTrail configuration"""
        actions = []
        
        # Check if trails exist
        trails = cloudtrail_results.get('trails', {}).get('Trails', [])
        if not trails:
            actions.append({
                'action': 'create_cloudtrail',
                'severity': 'HIGH',
                'description': 'No CloudTrail trails found in organization',
                'dry_run': config.DRY_RUN
            })
            
        return actions
    
    def _generate_recommendations(self) -> List[Dict[str, Any]]:
        """Generate general recommendations"""
        recommendations = []
        
        # Add MITRE ATT&CK mapping recommendations
        for attack_id, attack_info in config.MITRE_ATTACK_MAP.items():
            recommendations.append({
                'attack_id': attack_id,
                'name': attack_info['name'],
                'description': attack_info['description'],
                'severity': attack_info['severity'],
                'recommendation': f'Implement controls to prevent {attack_info["name"]}'
            })
            
        return recommendations
    
    def save_plan(self, filename: Optional[str] = None) -> str:
        """Save the plan to a file"""
        if not self.plan:
            raise ValueError("No plan generated. Please generate a plan first.")
            
        if not filename:
            filename = f"{config.OUTPUT_DIR}/remediation_plan_{config.TIMESTAMP}.json"
            
        with open(filename, 'w') as f:
            json.dump(self.plan, f, indent=2, default=str)
            
        logger.info(f"Plan saved to {filename}")
        return filename

def main():
    # Load scan results (this would typically come from scanner.py)
    try:
        # In a real implementation, this would load the scan results
        scan_results = {
            "organization": {"error": "No data loaded"},
            "compliance": {"error": "No data loaded"},
            "config": {"error": "No data loaded"},
            "cloudtrail": {"error": "No data loaded"}
        }
        
        planner = GovernancePlanner()
        planner.load_scan_results(scan_results)
        plan = planner.generate_plan()
        
        if config.DRY_RUN:
            logger.info("Dry-run mode enabled. Plan generated but no actions will be taken.")
            
        plan_file = planner.save_plan()
        logger.info(f"Remediation plan generated: {plan_file}")
        
        return plan
        
    except Exception as e:
        logger.error(f"Error in planner: {e}")
        raise

if __name__ == "__main__":
    main()
