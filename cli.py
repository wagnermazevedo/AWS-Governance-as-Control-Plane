# cli.py

import argparse
import logging
import sys
from scanner import main as scan_main
from planner import main as plan_main
from remediator import main as remediate_main
import config

def setup_logging():
    """Setup logging configuration"""
    logging.basicConfig(
        level=getattr(logging, config.LOG_LEVEL),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

def build_parser():
    """Build command line argument parser"""
    parser = argparse.ArgumentParser(description='AWS Governance Control Plane')
    
    # Global arguments
    parser.add_argument('--profile', help='AWS profile name')
    parser.add_argument('--region', default=config.AWS_REGION, help='AWS region')
    parser.add_argument('--dry-run', action='store_true', 
                       help='Enable dry-run mode (no actual changes)')
    parser.add_argument('--output-dir', default=config.OUTPUT_DIR, 
                       help='Output directory for results')
    
    # Subcommands
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Scan AWS environment for governance issues')
    scan_parser.add_argument('--output-file', help='Output file for scan results')
    
    # Plan command
    plan_parser = subparsers.add_parser('plan', help='Generate remediation plan')
    plan_parser.add_argument('--scan-results', required=True, 
                            help='Path to scan results JSON file')
    
    # Remediate command
    remediate_parser = subparsers.add_parser('remediate', help='Execute remediation actions')
    remediate_parser.add_argument('--plan-file', required=True, 
                                 help='Path to plan JSON file')
    
    return parser

def main():
    """Main entry point"""
    setup_logging()
    
    parser = build_parser()
    args = parser.parse_args()
    
    # Configure global settings
    if args.profile:
        config.AWS_PROFILE = args.profile
    
    if args.region:
        config.AWS_REGION = args.region
        
    if args.dry_run:
        config.DRY_RUN = True
        logging.info("Dry-run mode enabled")
        
    if args.output_dir:
        config.OUTPUT_DIR = args.output_dir
    
    # Execute command
    try:
        if args.command == 'scan':
            scan_main()
            
        elif args.command == 'plan':
            plan_main()
            
        elif args.command == 'remediate':
            remediate_main()
            
        else:
            parser.print_help()
            
    except Exception as e:
        logging.error(f"Command failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
