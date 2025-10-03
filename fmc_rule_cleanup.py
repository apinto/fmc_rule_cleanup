#!/usr/bin/env python3
"""
FMC Access Rule Hit Count Analysis and Auto-Disable Script

This script analyzes Cisco FMC access control rules based on hit counts
and automatically disables unused rules that meet specific criteria.

Author: Artur Pinto (arturj.pinto@gmail.com)
"""

import argparse
import datetime
import json
import logging
import sys
import time
from typing import Dict, List, Optional

try:
    import fmcapi
except ImportError:
    fmcapi = None


class FMCRuleManager:
    """Manages FMC access rule operations including hit count analysis and rule disabling."""
    
    def __init__(self, host: str, username: str, password: str, device_name: str,
                 autodeploy: bool = False, page_limit: int = 500, debug: bool = False,
                 timeout: int = 10, log_file: Optional[str] = None,
                 max_rules_to_disable: int = 1000, dry_run: bool = False,
                 exclude_zones: Optional[List[str]] = None, year_threshold: int = None,
                 rule_actions: Optional[List[str]] = None):
        """
        Initialize FMC Rule Manager.
        
        Args:
            host: FMC host IP address
            username: FMC username
            password: FMC password  
            device_name: Target device name
            autodeploy: Enable auto-deployment
            page_limit: API page limit for queries
            debug: Enable debug logging
            timeout: API timeout in seconds
            log_file: Log file name (optional)
            max_rules_to_disable: Maximum number of rules to disable per run
            dry_run: If True, simulate actions without making changes
            exclude_zones: List of zones to exclude from rule processing
            year_threshold: Consider rules created before this year for disabling (default: current year - 1)
            rule_actions: List of rule actions to consider (ALLOW, BLOCK, or both)
        """
        self.host = host
        self.username = username
        self.password = password
        self.device_name = device_name
        self.autodeploy = autodeploy
        self.page_limit = page_limit
        self.debug = debug
        self.timeout = timeout
        self.log_file = log_file
        self.max_rules_to_disable = max_rules_to_disable
        self.dry_run = dry_run
        self.exclude_zones = exclude_zones or []
        # Set default year threshold to previous year if not specified
        self.year_threshold = year_threshold if year_threshold is not None else datetime.datetime.now().year - 1
        self.rule_actions = rule_actions or ['ALLOW']
        
        # Check if fmcapi is available
        if fmcapi is None:
            raise ImportError("fmcapi module is required. Install with: pip install fmcapi")
        
        # Setup logging
        self._setup_logging()
        
    def _setup_logging(self) -> None:
        """Configure logging settings."""
        log_format = '%(asctime)s - %(levelname)s - %(message)s'
        log_level = logging.DEBUG if self.debug else logging.INFO
        
        if self.log_file:
            logging.basicConfig(
                level=log_level,
                format=log_format,
                handlers=[
                    logging.FileHandler(self.log_file),
                    logging.StreamHandler(sys.stdout)
                ]
            )
        else:
            logging.basicConfig(level=log_level, format=log_format)
            
    def _is_rule_in_excluded_zone(self, rule_data: Dict) -> bool:
        """
        Check if rule involves any excluded zones.
        
        Args:
            rule_data: Rule data dictionary from FMC API
            
        Returns:
            True if rule should be excluded, False otherwise
        """
        if not self.exclude_zones:
            return False
            
        # Check source zones
        if "sourceZones" in rule_data and "objects" in rule_data["sourceZones"]:
            for zone_obj in rule_data["sourceZones"]["objects"]:
                if zone_obj.get("name") in self.exclude_zones:
                    return True
                    
        # Check destination zones
        if "destinationZones" in rule_data and "objects" in rule_data["destinationZones"]:
            for zone_obj in rule_data["destinationZones"]["objects"]:
                if zone_obj.get("name") in self.exclude_zones:
                    return True
                    
        return False
        
    def _should_disable_rule(self, rule_data: Dict, current_time: str) -> tuple[bool, str]:
        """
        Determine if a rule should be disabled based on criteria.
        
        Args:
            rule_data: Rule data dictionary from FMC API
            current_time: Current timestamp string
            
        Returns:
            Tuple of (should_disable: bool, reason: str)
        """
        rule_name = rule_data.get("name", "Unknown")
        
        # Check if rule is in excluded zone
        if self._is_rule_in_excluded_zone(rule_data):
            logging.info(f"Rule '{rule_name}' skipped - involves excluded zone")
            return False, "Rule involves excluded zone"
            
        # Check if rule is enabled and has a matching action
        rule_action = rule_data.get("action", "")
        if not (rule_data.get("enabled") and rule_action in self.rule_actions):
            return False, f"Rule is not enabled or action '{rule_action}' not in allowed actions {self.rule_actions}"
            
        # Check comment history
        if "commentHistoryList" in rule_data:
            first_comment = rule_data["commentHistoryList"][0]
            first_comment_date = first_comment.get("date", "")
            first_comment_text = first_comment.get("comment", "")
            
            # Check for previous script comments
            if "DisabledByHitCountScript" in first_comment_text:
                return True, f"Rule previously marked by script: {first_comment_text}"
                
            # Check if rule is old (created before specified year threshold)
            try:
                year = int(first_comment_date.split("-")[0])
                if year < self.year_threshold:
                    return True, f"Rule created before {self.year_threshold} (first comment: {first_comment_date})"
            except (ValueError, IndexError):
                logging.warning(f"Could not parse date for rule '{rule_name}': {first_comment_date}")
                
        else:
            # No comment history - disable
            return True, "No comment history found"
            
        return False, "Rule does not meet disable criteria"
        
    def analyze_and_disable_rules(self) -> Dict[str, int]:
        """
        Main method to analyze hit counts and disable unused rules.
        
        Returns:
            Dictionary with operation statistics
        """
        stats = {
            "total_rules_analyzed": 0,
            "zero_hit_rules": 0,
            "rules_disabled": 0,
            "rules_skipped": 0,
            "disabled_rules_details": []  # List to store details of disabled rules
        }
        
        current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        try:
            with fmcapi.FMC(
                host=self.host,
                username=self.username,
                password=self.password,
                autodeploy=self.autodeploy,
                limit=self.page_limit,
                file_logging=self.log_file,
                debug=self.debug,
                timeout=self.timeout
            ) as fmc_client:
                
                logging.info(f"Starting hit count analysis for device '{self.device_name}' at {current_time}")
                if self.dry_run:
                    logging.info("DRY RUN MODE - No changes will be made to FMC")
                
                # Get device information
                device = fmcapi.DeviceRecords(fmc=fmc_client, name=self.device_name)
                device.get()
                
                if not hasattr(device, 'accessPolicy') or not device.accessPolicy:
                    logging.error(f"No access policy found for device '{self.device_name}'")
                    return stats
                    
                acp_id = device.accessPolicy["id"]
                logging.info(f"Found access policy ID: {acp_id}")
                
                # Get hit counts
                hit_counter = fmcapi.HitCounts(
                    fmc=fmc_client, 
                    acp_id=acp_id, 
                    device_name=self.device_name
                )
                
                hit_count_result = hit_counter.get()
                
                if "items" not in hit_count_result:
                    logging.error("No hit count data received from FMC")
                    return stats
                    
                # Identify rules with zero hits
                zero_hit_rule_ids = []
                for item in hit_count_result["items"]:
                    stats["total_rules_analyzed"] += 1
                    rule_name = item["rule"]["name"]
                    rule_type = item["rule"].get("type", "Unknown")
                    hit_count = item["hitCount"]
                    
                    logging.debug(f"Rule '{rule_name}' has {hit_count} hits")
                    
                    if hit_count == 0:
                        # Only process AccessRule types, skip default actions and other special rule types
                        if rule_type == "AccessRule":
                            zero_hit_rule_ids.append(item["rule"]["id"])
                            stats["zero_hit_rules"] += 1
                        else:
                            logging.debug(f"Skipping rule '{rule_name}' with type '{rule_type}' - not a regular access rule")
                        
                logging.info(f"Found {len(zero_hit_rule_ids)} rules with zero hit counts")
                
                # Process each zero-hit rule
                disabled_count = 0
                for rule_id in zero_hit_rule_ids:
                    if disabled_count >= self.max_rules_to_disable:
                        logging.info(f"Reached maximum rule disable limit: {self.max_rules_to_disable}")
                        break
                        
                    try:
                        # Get detailed rule information
                        access_rule = fmcapi.AccessRules(
                            fmc=fmc_client, 
                            acp_id=acp_id, 
                            id=rule_id
                        )
                        rule_data = access_rule.get()
                        rule_name = rule_data.get("name", "Unknown")
                        
                        should_disable, reason = self._should_disable_rule(rule_data, current_time)
                        
                        if should_disable:
                            # Extract first comment if available
                            first_comment = ""
                            if "commentHistoryList" in rule_data and rule_data["commentHistoryList"]:
                                first_comment_data = rule_data["commentHistoryList"][0]
                                first_comment = first_comment_data.get("comment", "")
                                first_comment_date = first_comment_data.get("date", "")
                                if first_comment and first_comment_date:
                                    first_comment = f"{first_comment} ({first_comment_date})"
                            
                            # Store rule details for summary
                            rule_details = {
                                "name": rule_name,
                                "id": rule_id,
                                "first_comment": first_comment or "No comment history",
                                "reason": reason
                            }
                            
                            if self.dry_run:
                                logging.info(f"[DRY RUN] Would disable rule '{rule_name}' - {reason}")
                                stats["rules_disabled"] += 1
                                stats["disabled_rules_details"].append(rule_details)
                            else:
                                # Disable the rule and add comment
                                access_rule.enabled = False
                                comment = f"DisabledByHitCountScript {current_time} - {reason}"
                                access_rule.new_comments(action="add", value=comment)
                                access_rule.post()
                                
                                logging.info(f"Disabled rule '{rule_name}' - {reason}")
                                stats["rules_disabled"] += 1
                                stats["disabled_rules_details"].append(rule_details)
                                
                            disabled_count += 1
                        else:
                            logging.debug(f"Skipped rule '{rule_name}' - {reason}")
                            stats["rules_skipped"] += 1
                            
                    except Exception as e:
                        logging.error(f"Error processing rule ID {rule_id}: {str(e)}")
                        continue
                        
                logging.info("Hit count analysis completed")
                
        except Exception as e:
            logging.error(f"FMC connection or API error: {str(e)}")
            raise
            
        return stats


def format_disabled_rules_table(disabled_rules: List[Dict]) -> str:
    """
    Format disabled rules data into a readable table.
    
    Args:
        disabled_rules: List of disabled rule dictionaries
        
    Returns:
        Formatted table string
    """
    if not disabled_rules:
        return "No rules were disabled."
    
    # Calculate column widths
    name_width = max(len("Rule Name"), max(len(rule["name"]) for rule in disabled_rules))
    id_width = len("ECF40C21-3F6A-0ed3-0000-000268479583")  # Fixed width for rule IDs
    comment_width = max(len("First Comment"), max(len(rule["first_comment"]) for rule in disabled_rules))
    reason_width = max(len("Disable Reason"), max(len(rule["reason"]) for rule in disabled_rules))
    
    # Limit column widths for readability
    name_width = min(name_width, 35)
    comment_width = min(comment_width, 55)
    reason_width = min(reason_width, 45)
    
    # Create table format
    separator = "+" + "-" * (name_width + 2) + "+" + "-" * (id_width + 2) + "+" + "-" * (comment_width + 2) + "+" + "-" * (reason_width + 2) + "+"
    header_format = f"| {{:<{name_width}}} | {{:<{id_width}}} | {{:<{comment_width}}} | {{:<{reason_width}}} |"
    row_format = f"| {{:<{name_width}.{name_width}}} | {{:<{id_width}}} | {{:<{comment_width}.{comment_width}}} | {{:<{reason_width}.{reason_width}}} |"
    
    # Build table
    lines = [
        separator,
        header_format.format("Rule Name", "Rule ID", "First Comment", "Disable Reason"),
        separator
    ]
    
    for rule in disabled_rules:
        lines.append(row_format.format(
            rule["name"],
            rule["id"], 
            rule["first_comment"],
            rule["reason"]
        ))
    
    lines.append(separator)
    
    return "\n".join(lines)


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="FMC Access Rule Hit Count Analysis and Auto-Disable Script",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --host 192.168.1.100 --username admin --password secret --device firewall01.example.local
  %(prog)s --host 192.168.1.100 --username admin --password secret --device firewall01.example.local --dry-run
  %(prog)s --host 192.168.1.100 --username admin --password secret --device firewall01.example.local --max-rules 500 --exclude-zones TRUSTED DMZ
  %(prog)s --host 192.168.1.100 --username admin --password secret --device firewall01.example.local --year-threshold 2022 --rule-actions ALLOW BLOCK
  %(prog)s --host 192.168.1.100 --username admin --password secret --device firewall01.example.local --rule-actions BLOCK --dry-run
        """
    )
    
    # Required arguments
    required = parser.add_argument_group('required arguments')
    required.add_argument(
        '--host', 
        required=True,
        help='FMC host IP address'
    )
    required.add_argument(
        '--username',
        required=True, 
        help='FMC username'
    )
    required.add_argument(
        '--password',
        required=True,
        help='FMC password'
    )
    required.add_argument(
        '--device',
        required=True,
        dest='device_name',
        help='Target device name (cluster name)'
    )
    
    # Optional arguments
    parser.add_argument(
        '--autodeploy',
        action='store_true',
        default=False,
        help='Enable automatic deployment (default: False)'
    )
    parser.add_argument(
        '--page-limit',
        type=int,
        default=500,
        help='API page limit for queries (default: 500)'
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        default=False,
        help='Enable debug logging (default: False)'
    )
    parser.add_argument(
        '--timeout',
        type=int,
        default=10,
        help='API timeout in seconds (default: 10)'
    )
    parser.add_argument(
        '--log-file',
        help='Log file name (default: log to console only)'
    )
    parser.add_argument(
        '--max-rules',
        type=int,
        default=1000,
        dest='max_rules_to_disable',
        help='Maximum number of rules to disable per run (default: 1000)'
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        default=False,
        help='Simulate actions without making changes to FMC (default: False)'
    )
    parser.add_argument(
        '--exclude-zones',
        nargs='*',
        default=['TRUSTED'],
        help='List of zones to exclude from processing (default: TRUSTED)'
    )
    parser.add_argument(
        '--year-threshold',
        type=int,
        default=datetime.datetime.now().year - 1,
        help=f'Consider rules created before this year for disabling (default: {datetime.datetime.now().year - 1})'
    )
    parser.add_argument(
        '--rule-actions',
        nargs='*',
        choices=['ALLOW', 'BLOCK'],
        default=['ALLOW'],
        help='Rule actions to consider for disabling (default: ALLOW)'
    )
    
    return parser.parse_args()


def main() -> int:
    """Main function."""
    try:
        args = parse_arguments()
        
        # Create FMC Rule Manager instance
        manager = FMCRuleManager(
            host=args.host,
            username=args.username,
            password=args.password,
            device_name=args.device_name,
            autodeploy=args.autodeploy,
            page_limit=args.page_limit,
            debug=args.debug,
            timeout=args.timeout,
            log_file=args.log_file,
            max_rules_to_disable=args.max_rules_to_disable,
            dry_run=args.dry_run,
            exclude_zones=args.exclude_zones,
            year_threshold=args.year_threshold,
            rule_actions=args.rule_actions
        )
        
        # Run the analysis
        stats = manager.analyze_and_disable_rules()
        
        # Print summary
        print("\n" + "="*50)
        print("OPERATION SUMMARY")
        print("="*50)
        print(f"Total rules analyzed: {stats['total_rules_analyzed']}")
        print(f"Rules with zero hits: {stats['zero_hit_rules']}")
        print(f"Rules disabled: {stats['rules_disabled']}")
        print(f"Rules skipped: {stats['rules_skipped']}")
        if args.dry_run:
            print("\nNOTE: This was a dry run - no changes were made to FMC")
        
        # Display disabled rules table
        if stats['disabled_rules_details']:
            print(f"\nDISABLED RULES DETAILS ({len(stats['disabled_rules_details'])} rules):")
            print("="*50)
            disabled_rules_table = format_disabled_rules_table(stats['disabled_rules_details'])
            print(disabled_rules_table)
            
            # Also log the table to debug log
            logging.info("DISABLED RULES DETAILS:")
            for line in disabled_rules_table.split('\n'):
                logging.info(line)
        else:
            print("\nNo rules were disabled during this operation.")
            
        print("="*50)
        
        return 0
        
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        return 1
    except Exception as e:
        logging.error(f"Script execution failed: {str(e)}")
        return 1


if __name__ == "__main__":
    sys.exit(main())