#!/usr/bin/env python3
"""
Abnormal Security CLI Tool

This script provides command-line capabilities for interacting with the Abnormal Security API,
including:
- Testing API connectivity
- Managing threats and cases
- Visualizing security data
- Implementing priority management
- Categorizing threats by attack type, vector, strategy, and impersonated party
- Bulk remediation operations
"""

import os
import sys
import json
import time
import argparse
import subprocess
from datetime import datetime, timedelta
from dotenv import load_dotenv
import textwrap
import logging

# Load API token from environment
load_dotenv()
token = os.getenv('ABNORMAL_API_TOKEN')
if not token:
    print("ERROR: ABNORMAL_API_TOKEN not found in .env file")
    sys.exit(1)

# Base URL
base_url = "https://api.abnormalplatform.com"

# Threat categorization options based on the screenshot
THREAT_CATEGORIES = {
    "attack_type": [
        "Internal-to-Internal Attacks (Email Account Takeover)",
        "Spam",
        "Reconnaissance", 
        "Scam",
        "Social Engineering (BEC)",
        "Phishing: Credential",
        "Invoice/Payment Fraud (BEC)",
        "Malware",
        "Extortion",
        "Phishing: Sensitive Data",
        "Other"
    ],
    "attack_vector": [
        "Link",
        "Attachment", 
        "Text",
        "Others",
        "QR Code"
    ],
    "attack_strategy": [
        "Name Impersonation",
        "Internal Compromised Email Account",
        "External Compromised Email Account", 
        "Spoofed Email",
        "Unknown Sender",
        "Covid 19 Related Attack"
    ],
    "impersonated_party": [
        "VIP",
        "Assistants",
        "Employee (other)",
        "Brand",
        "Known Partners",
        "Automated System (Internal)",
        "Automated System (External)",
        "Unknown Partner",
        "None / Others"
    ]
}

# ANSI color codes for terminal output
class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    GRAY = "\033[90m"

def make_api_request(endpoint, method="GET", data=None, params=None):
    """Make a request to the Abnormal Security API"""
    url = f"{base_url}{endpoint}"
    
    # Build curl command
    cmd = [
        "curl",
        "-s",                                   # Silent mode
        "-k",                                   # Skip SSL verification
        "-X", method,                           # HTTP method
        "-H", f"Authorization: Bearer {token}", # Auth header
        "-H", "Content-Type: application/json", # Content-Type header
        "-m", "30",                             # Timeout in seconds
    ]
    
    # Add query parameters
    if params:
        param_strings = []
        for key, value in params.items():
            param_strings.append(f"{key}={value}")
        url = f"{url}?{'&'.join(param_strings)}"
    
    # Add request body for POST/PUT
    if data and method in ["POST", "PUT"]:
        cmd.extend(["-d", json.dumps(data)])
    
    # Add URL as the last argument
    cmd.append(url)
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=45)
        
        if result.returncode == 0:
            try:
                return json.loads(result.stdout)
            except json.JSONDecodeError:
                print(f"{Colors.RED}Invalid JSON response:{Colors.RESET}")
                print(result.stdout[:500])
                return None
        else:
            print(f"{Colors.RED}Error executing curl command:{Colors.RESET}")
            print(f"Command: {' '.join(cmd)}")
            print(f"Return code: {result.returncode}")
            print(f"Error: {result.stderr}")
            return None
            
    except subprocess.TimeoutExpired:
        print(f"{Colors.RED}Error: Command timed out after 45 seconds{Colors.RESET}")
        return None
    except Exception as e:
        print(f"{Colors.RED}Error: {e}{Colors.RESET}")
        return None

def test_endpoints():
    """Test key API endpoints and display results"""
    endpoints = [
        "/v1/cases",
        "/v1/threats",
        "/v1/aggregations/dashboard_summary",
        "/v1/detection360/reports"
    ]
    
    all_success = True
    print(f"\n{Colors.BOLD}=== Testing Abnormal Security API Endpoints ==={Colors.RESET}\n")
    
    for endpoint in endpoints:
        print(f"{Colors.BOLD}Testing:{Colors.RESET} {endpoint}")
        start_time = time.time()
        data = make_api_request(endpoint)
        elapsed = time.time() - start_time
        
        if data:
            print(f"{Colors.GREEN}✓ Success{Colors.RESET} (took {elapsed:.2f}s)")
            
            # Show a sample of the data
            if endpoint == "/v1/cases":
                total = data.get("total", 0)
                cases = data.get("cases", [])
                print(f"  {Colors.CYAN}Found {total} cases{Colors.RESET}")
                if cases:
                    print(f"  {Colors.GRAY}Sample case ID: {cases[0].get('caseId', 'unknown')}{Colors.RESET}")
            
            elif endpoint == "/v1/threats":
                total = data.get("total", 0)
                threats = data.get("threats", [])
                print(f"  {Colors.CYAN}Found {total} threats{Colors.RESET}")
                if threats:
                    print(f"  {Colors.GRAY}Sample threat ID: {threats[0].get('threatId', 'unknown')}{Colors.RESET}")
            
            elif endpoint == "/v1/aggregations/dashboard_summary":
                if isinstance(data, list) and len(data) > 0:
                    if "attack_stopped" in data[0]:
                        attack_count = data[0]["attack_stopped"][0].get("attack_count", 0)
                        prev_count = data[0]["attack_stopped"][0].get("prev_attack_count", 0)
                        change = ((attack_count - prev_count) / prev_count * 100) if prev_count > 0 else 0
                        direction = "↑" if change >= 0 else "↓"
                        print(f"  {Colors.CYAN}Attacks stopped: {attack_count} ({direction} {abs(change):.1f}%){Colors.RESET}")
            
            elif endpoint == "/v1/detection360/reports":
                print(f"  {Colors.CYAN}Detection 360 reports available{Colors.RESET}")
                
        else:
            all_success = False
            print(f"{Colors.RED}✗ Failed{Colors.RESET}")
    
    print(f"\n{Colors.BOLD}Overall API Test: {'SUCCESS' if all_success else 'FAILED'}{Colors.RESET}")
    return all_success

def prioritize_threat(threat):
    """
    Assign a priority level (P1-P4) to a threat based on characteristics
    
    P1 (Critical): High confidence phishing, BEC, or ATO
    P2 (High): Medium confidence threats or targeting execs
    P3 (Medium): Low confidence threats needing investigation
    P4 (Low): Very low confidence or false positive patterns
    """
    # Default is P3 (Medium)
    priority = 3
    confidence = threat.get("confidence", "").lower()
    attack_type = threat.get("attackType", "").lower()
    subject = threat.get("subject", "").lower()
    target_users = threat.get("targetUsers", [])
    
    # Critical threats - P1
    if confidence == "high" and any(t in attack_type for t in ["phishing", "account", "compromise", "bec"]):
        priority = 1
    # Check for executive targeting
    elif any(("exec" in user.get("title", "").lower() or "cxo" in user.get("title", "").lower()) for user in target_users):
        priority = 1 if confidence != "low" else 2
    # High priority threats - P2  
    elif confidence == "medium" or "urgent" in subject or "password" in subject:
        priority = 2
    # Low priority threats - P4
    elif confidence == "low" and any(t in attack_type for t in ["spam", "marketing"]):
        priority = 4
    
    # Map priority number to label and color
    priority_map = {
        1: (f"{Colors.RED}P1 (Critical){Colors.RESET}", "critical"),
        2: (f"{Colors.MAGENTA}P2 (High){Colors.RESET}", "high"),
        3: (f"{Colors.YELLOW}P3 (Medium){Colors.RESET}", "medium"), 
        4: (f"{Colors.GREEN}P4 (Low){Colors.RESET}", "low")
    }
    
    return {"level": priority, "display": priority_map[priority][0], "category": priority_map[priority][1]}

def get_threats(limit=10, detailed=False):
    """Retrieve and display threats with priority management"""
    print(f"\n{Colors.BOLD}=== Recent Abnormal Security Threats ==={Colors.RESET}\n")
    
    # Get threats data - API doesn't support limit parameter directly
    params = {}
    data = make_api_request("/v1/threats", params=params)
    
    if not data or "threats" not in data:
        print(f"{Colors.RED}Failed to retrieve threats{Colors.RESET}")
        return
    
    threats = data.get("threats", [])
    total = data.get("total", 0)
    
    print(f"Displaying {len(threats)} of {total} total threats\n")
    
    # Keep track of priorities for summary
    priority_counts = {1: 0, 2: 0, 3: 0, 4: 0}
    
    # Display each threat with priority
    for idx, threat in enumerate(threats):
        threat_id = threat.get("threatId", "unknown")
        
        # Get detailed threat info if requested
        if detailed:
            detailed_data = make_api_request(f"/v1/threats/{threat_id}")
            if detailed_data:
                threat = detailed_data
        
        # Extract threat details
        subject = threat.get("subject", "No subject")
        received_time = threat.get("receivedTime", "Unknown time")
        attack_type = threat.get("attackType", "Unknown type")
        confidence = threat.get("confidence", "Unknown")
        
        # Determine priority
        priority = prioritize_threat(threat)
        priority_counts[priority["level"]] += 1
        
        # Format and display the threat
        print(f"{Colors.BOLD}Threat {idx+1}:{Colors.RESET} {priority['display']}")
        print(f"  ID: {threat_id}")
        print(f"  Subject: {textwrap.shorten(subject, width=60)}")
        print(f"  Type: {attack_type} ({confidence} confidence)")
        print(f"  Time: {received_time}")
        
        # Show remediation options
        print(f"  {Colors.BOLD}Actions:{Colors.RESET}")
        if priority["level"] <= 2:  # P1 or P2
            print(f"    - Remediate: ./abnormal_cli.py remediate {threat_id}")
            print(f"    - Quarantine: ./abnormal_cli.py quarantine {threat_id}")
        print(f"    - Details: ./abnormal_cli.py threat-details {threat_id}")
        print()
    
    # Display priority distribution
    display_priority_summary(priority_counts)

def display_priority_summary(priority_counts):
    """Display a simple ASCII visualization of priority distribution"""
    total = sum(priority_counts.values())
    if total == 0:
        return
    
    print(f"\n{Colors.BOLD}Priority Distribution:{Colors.RESET}")
    
    # Map for visual display
    labels = {
        1: f"{Colors.RED}P1 (Critical){Colors.RESET}",
        2: f"{Colors.MAGENTA}P2 (High){Colors.RESET}",
        3: f"{Colors.YELLOW}P3 (Medium){Colors.RESET}",
        4: f"{Colors.GREEN}P4 (Low){Colors.RESET}"
    }
    
    # Display bar chart
    max_width = 40
    for level in range(1, 5):
        count = priority_counts[level]
        percentage = (count / total) * 100
        bar_width = int((count / total) * max_width)
        bar = "█" * bar_width
        print(f"{labels[level]}: {bar} {count} ({percentage:.1f}%)")
    
    # Priority-based recommendations
    print(f"\n{Colors.BOLD}Recommended Actions:{Colors.RESET}")
    if priority_counts[1] > 0:
        print(f"• {Colors.RED}Critical:{Colors.RESET} {priority_counts[1]} P1 threats require immediate attention")
    if priority_counts[2] > 0:
        print(f"• {Colors.MAGENTA}High:{Colors.RESET} Address {priority_counts[2]} P2 threats within 4 hours")
    if priority_counts[3] > 0:
        print(f"• {Colors.YELLOW}Medium:{Colors.RESET} Investigate {priority_counts[3]} P3 threats within 24 hours")
    if priority_counts[4] > 0:
        print(f"• {Colors.GREEN}Low:{Colors.RESET} Review {priority_counts[4]} P4 threats as time permits")

def get_threat_details(threat_id):
    """Get and display detailed information about a specific threat"""
    print(f"\n{Colors.BOLD}=== Threat Details ==={Colors.RESET}\n")
    
    data = make_api_request(f"/v1/threats/{threat_id}")
    if not data:
        print(f"{Colors.RED}Failed to retrieve threat details for {threat_id}{Colors.RESET}")
        return
    
    # Determine priority
    priority = prioritize_threat(data)
    
    # Display threat details
    print(f"{Colors.BOLD}Threat ID:{Colors.RESET} {threat_id} {priority['display']}")
    print(f"{Colors.BOLD}Subject:{Colors.RESET} {data.get('subject', 'No subject')}")
    print(f"{Colors.BOLD}Received Time:{Colors.RESET} {data.get('receivedTime', 'Unknown')}")
    print(f"{Colors.BOLD}Attack Type:{Colors.RESET} {data.get('attackType', 'Unknown')}")
    print(f"{Colors.BOLD}Confidence:{Colors.RESET} {data.get('confidence', 'Unknown')}")
    
    # Show sender details
    sender = data.get('sender', {})
    print(f"\n{Colors.BOLD}Sender Information:{Colors.RESET}")
    print(f"  Name: {sender.get('name', 'Unknown')}")
    print(f"  Email: {sender.get('email', 'Unknown')}")
    print(f"  Domain: {sender.get('domain', 'Unknown')}")
    
    # Show target details
    targets = data.get('targetUsers', [])
    print(f"\n{Colors.BOLD}Target Recipients ({len(targets)}):{Colors.RESET}")
    for idx, target in enumerate(targets[:5]):  # Show up to 5 targets
        print(f"  {idx+1}. {target.get('name', 'Unknown')} ({target.get('email', 'Unknown')})")
    if len(targets) > 5:
        print(f"  ...and {len(targets) - 5} more recipients")
    
    # Recommended actions based on priority
    print(f"\n{Colors.BOLD}Recommended Actions:{Colors.RESET}")
    if priority["level"] == 1:
        print(f"  {Colors.RED}CRITICAL:{Colors.RESET} Immediate action required")
        print(f"  - Quarantine message")
        print(f"  - Reset user password if credentials potentially compromised")
        print(f"  - Analyze lateral movement risk")
    elif priority["level"] == 2:
        print(f"  {Colors.MAGENTA}HIGH:{Colors.RESET} Action required within 4 hours")
        print(f"  - Quarantine message")
        print(f"  - Notify targeted users")
    elif priority["level"] == 3:
        print(f"  {Colors.YELLOW}MEDIUM:{Colors.RESET} Action required within 24 hours")
        print(f"  - Investigate further")
        print(f"  - Consider quarantine based on investigation")
    else:
        print(f"  {Colors.GREEN}LOW:{Colors.RESET} Action as time permits")
        print(f"  - Review for potential false positive")
    
    # Available actions
    print(f"\n{Colors.BOLD}Available Actions:{Colors.RESET}")
    print(f"  Remediate: ./abnormal_cli.py remediate {threat_id}")
    print(f"  Quarantine: ./abnormal_cli.py quarantine {threat_id}")
    print(f"  Mark False Positive: ./abnormal_cli.py mark-fp {threat_id}")

def take_action(threat_id, action, action_data=None):
    """Take action on a threat (remediate, quarantine, etc.) with detailed logging"""
    reason = action_data.get("reason") if action_data else None
    return take_action_with_logging(threat_id, action, action_data, reason)

def get_action_status(threat_id, action_id):
    """Get the status of an action taken on a threat"""
    print(f"\n{Colors.BOLD}=== Action Status ==={Colors.RESET}\n")
    print(f"Threat ID: {threat_id}")
    print(f"Action ID: {action_id}")
    
    data = make_api_request(f"/v1/threats/{threat_id}/actions/{action_id}")
    
    if data:
        status = data.get("status", "unknown")
        status_color = Colors.GREEN if status == "completed" else (Colors.YELLOW if status == "in_progress" else Colors.RED)
        
        print(f"\nStatus: {status_color}{status}{Colors.RESET}")
        print(f"Created: {data.get('createdTime', 'unknown')}")
        
        if "completedTime" in data:
            print(f"Completed: {data.get('completedTime')}")
        
        if "results" in data:
            print(f"\n{Colors.BOLD}Results:{Colors.RESET}")
            print(json.dumps(data["results"], indent=2))
    else:
        print(f"\n{Colors.RED}Failed to retrieve action status{Colors.RESET}")

def get_dashboard_summary():
    """Get and display a summary of security metrics"""
    print(f"\n{Colors.BOLD}=== Abnormal Security Dashboard Summary ==={Colors.RESET}\n")
    
    data = make_api_request("/v1/aggregations/dashboard_summary")
    
    if not data or not isinstance(data, list):
        print(f"{Colors.RED}Failed to retrieve dashboard summary{Colors.RESET}")
        return
    
    # Extract metrics from the response
    attack_stopped = None
    attack_frequency = []
    trending_attacks = []
    
    for item in data:
        if "attack_stopped" in item:
            attack_stopped = item["attack_stopped"][0]
        elif "attack_frequency" in item:
            attack_frequency = item["attack_frequency"]
        elif "trending_attacks" in item:
            trending_attacks = item["trending_attacks"]
    
    # Display attack stopped metrics
    if attack_stopped:
        attack_count = attack_stopped.get("attack_count", 0)
        prev_count = attack_stopped.get("prev_attack_count", 0)
        change = ((attack_count - prev_count) / prev_count * 100) if prev_count > 0 else 0
        
        print(f"{Colors.BOLD}Attacks Stopped:{Colors.RESET} {attack_count}")
        if change > 0:
            print(f"  {Colors.RED}↑ {change:.1f}% increase{Colors.RESET} from previous period ({prev_count})")
        else:
            print(f"  {Colors.GREEN}↓ {abs(change):.1f}% decrease{Colors.RESET} from previous period ({prev_count})")
    
    # Display attack frequency
    if attack_frequency:
        print(f"\n{Colors.BOLD}Attack Frequency (Last 7 Days):{Colors.RESET}")
        
        # Group by date
        by_date = {}
        for item in attack_frequency:
            date = item.get("timestamp", "unknown")
            attack_type = item.get("attack_type", "unknown")
            count = item.get("attack_count", 0)
            
            if date not in by_date:
                by_date[date] = {}
            
            by_date[date][attack_type] = count
        
        # Display as simple ASCII chart
        for date in sorted(by_date.keys()):
            total = sum(by_date[date].values())
            print(f"  {date}: {total} attacks")
            
            for attack_type, count in sorted(by_date[date].items(), key=lambda x: x[1], reverse=True):
                bar = "█" * min(20, count)
                print(f"    {attack_type}: {bar} {count}")
    
    # Display trending attacks
    if trending_attacks:
        print(f"\n{Colors.BOLD}Trending Attack Types:{Colors.RESET}")
        
        for item in trending_attacks[:5]:  # Show top 5
            attack_type = item.get("attack_type", "unknown")
            count = item.get("count", 0)
            trend = item.get("trend", 0)
            
            trend_icon = "↑" if trend > 0 else ("↓" if trend < 0 else "-")
            trend_color = Colors.RED if trend > 0 else (Colors.GREEN if trend < 0 else Colors.RESET)
            
            print(f"  {attack_type}: {count} ({trend_color}{trend_icon} {abs(trend)}%{Colors.RESET})")

def show_help():
    """Display help information"""
    print(f"\n{Colors.BOLD}Abnormal Security CLI Tool{Colors.RESET}")
    print(f"\nUsage: ./abnormal_cli.py [command] [arguments]")
    
    print(f"\n{Colors.BOLD}Available Commands:{Colors.RESET}")
    print(f"  {Colors.CYAN}test{Colors.RESET}                    Test API connectivity to all endpoints")
    print(f"  {Colors.CYAN}threats{Colors.RESET} [limit]          List recent threats with priority management")
    print(f"  {Colors.CYAN}threats-detailed{Colors.RESET} [limit] List detailed threat information")
    print(f"  {Colors.CYAN}threats-unlimited{Colors.RESET} [limit] List ALL threats (no API limits)")
    print(f"  {Colors.CYAN}threat-details{Colors.RESET} <id>      Get detailed information about a specific threat")
    print(f"  {Colors.CYAN}remediate{Colors.RESET} <id>           Remediate a specific threat")
    print(f"  {Colors.CYAN}quarantine{Colors.RESET} <id>          Quarantine a specific threat")
    print(f"  {Colors.CYAN}mark-fp{Colors.RESET} <id>             Mark a threat as a false positive")
    print(f"  {Colors.CYAN}action-status{Colors.RESET} <id> <action_id> Check the status of an action")
    print(f"  {Colors.CYAN}dashboard{Colors.RESET}                Display a summary of security metrics")
    print(f"  {Colors.CYAN}categories{Colors.RESET}               List all available threat categories")
    print(f"  {Colors.CYAN}threats-by-type{Colors.RESET} <type>   Filter threats by attack type")
    print(f"  {Colors.CYAN}threats-by-vector{Colors.RESET} <vector> Filter threats by attack vector")
    print(f"  {Colors.CYAN}threats-by-strategy{Colors.RESET} <strategy> Filter threats by attack strategy")
    print(f"  {Colors.CYAN}threats-by-party{Colors.RESET} <party> Filter threats by impersonated party")
    print(f"  {Colors.CYAN}threats-p1{Colors.RESET} [limit]       Show only P1 (Critical) threats")
    print(f"  {Colors.CYAN}threats-p2{Colors.RESET} [limit]       Show only P2 (High) threats")
    print(f"  {Colors.CYAN}threats-p3{Colors.RESET} [limit]       Show only P3 (Medium) threats")
    print(f"  {Colors.CYAN}threats-p4{Colors.RESET} [limit]       Show only P4 (Low) threats")
    print(f"  {Colors.CYAN}bulk-interactive{Colors.RESET}         Interactive bulk operations")
    print(f"  {Colors.CYAN}bulk-interactive-unlimited{Colors.RESET} Interactive bulk operations (UNLIMITED)")
    print(f"  {Colors.CYAN}remediation-history{Colors.RESET} [limit] Show recent remediation history")
    print(f"  {Colors.CYAN}false-positive-management{Colors.RESET} Interactive false positive management")
    print(f"  {Colors.CYAN}help{Colors.RESET}                     Display this help information")
    
    print(f"\n{Colors.BOLD}Examples:{Colors.RESET}")
    print(f"  ./abnormal_cli.py threats 20")
    print(f"  ./abnormal_cli.py threats-unlimited")
    print(f"  ./abnormal_cli.py threat-details 0ad4c0de-86c3-d4f1-f7c7-55663e2b9b25")
    print(f"  ./abnormal_cli.py remediate 0ad4c0de-86c3-d4f1-f7c7-55663e2b9b25")
    print(f"  ./abnormal_cli.py threats-by-type 'Phishing: Credential'")
    print(f"  ./abnormal_cli.py threats-p1 50")
    print(f"  ./abnormal_cli.py bulk-interactive")
    print(f"  ./abnormal_cli.py bulk-interactive-unlimited")
    print(f"  ./abnormal_cli.py remediation-history 20")
    print(f"  ./abnormal_cli.py false-positive-management")

def get_threats_by_category(category_type, category_value, limit=None, detailed=False):
    """Retrieve and display threats filtered by specific category"""
    print(f"\n{Colors.BOLD}=== Threats by {category_type.replace('_', ' ').title()} ==={Colors.RESET}\n")
    print(f"Filter: {category_value}")
    
    # Get all threats first (API doesn't support direct filtering)
    params = {}
    data = make_api_request("/v1/threats", params=params)
    
    if not data or "threats" not in data:
        print(f"{Colors.RED}Failed to retrieve threats{Colors.RESET}")
        return []
    
    threats = data.get("threats", [])
    total = data.get("total", 0)
    
    # Filter threats by category
    filtered_threats = []
    for threat in threats:
        if matches_category(threat, category_type, category_value):
            filtered_threats.append(threat)
    
    print(f"Found {len(filtered_threats)} threats matching '{category_value}' out of {total} total threats\n")
    
    # Apply limit if specified
    if limit and len(filtered_threats) > limit:
        filtered_threats = filtered_threats[:limit]
        print(f"Showing first {limit} threats (use --all to see all)\n")
    
    # Display filtered threats
    priority_counts = {1: 0, 2: 0, 3: 0, 4: 0}
    
    for idx, threat in enumerate(filtered_threats):
        threat_id = threat.get("threatId", "unknown")
        
        # Get detailed threat info if requested
        if detailed:
            detailed_data = make_api_request(f"/v1/threats/{threat_id}")
            if detailed_data:
                threat = detailed_data
        
        # Extract threat details
        subject = threat.get("subject", "No subject")
        received_time = threat.get("receivedTime", "Unknown time")
        attack_type = threat.get("attackType", "Unknown type")
        confidence = threat.get("confidence", "Unknown")
        
        # Determine priority
        priority = prioritize_threat(threat)
        priority_counts[priority["level"]] += 1
        
        # Format and display the threat
        print(f"{Colors.BOLD}Threat {idx+1}:{Colors.RESET} {priority['display']}")
        print(f"  ID: {threat_id}")
        print(f"  Subject: {textwrap.shorten(subject, width=60)}")
        print(f"  Type: {attack_type} ({confidence} confidence)")
        print(f"  Time: {received_time}")
        
        # Show remediation options
        print(f"  {Colors.BOLD}Actions:{Colors.RESET}")
        if priority["level"] <= 2:  # P1 or P2
            print(f"    - Remediate: ./abnormal_cli.py remediate {threat_id}")
            print(f"    - Quarantine: ./abnormal_cli.py quarantine {threat_id}")
        print(f"    - Details: ./abnormal_cli.py threat-details {threat_id}")
        print()
    
    # Display priority distribution for filtered threats
    if filtered_threats:
        display_priority_summary(priority_counts)
    
    return filtered_threats

def matches_category(threat, category_type, category_value):
    """Check if a threat matches the specified category"""
    if category_type == "attack_type":
        return threat.get("attackType", "").lower() == category_value.lower()
    elif category_type == "attack_vector":
        # Check attack vector in threat details
        attack_vector = threat.get("attackVector", "").lower()
        return attack_vector == category_value.lower()
    elif category_type == "attack_strategy":
        # Check attack strategy in threat details
        strategy = threat.get("attackStrategy", "").lower()
        return strategy == category_value.lower()
    elif category_type == "impersonated_party":
        # Check impersonated party in threat details
        impersonated = threat.get("impersonatedParty", "").lower()
        return impersonated == category_value.lower()
    return False

def list_categories():
    """Display all available threat categories"""
    print(f"\n{Colors.BOLD}=== Available Threat Categories ==={Colors.RESET}\n")
    
    for category_type, options in THREAT_CATEGORIES.items():
        print(f"{Colors.BOLD}{category_type.replace('_', ' ').title()}:{Colors.RESET}")
        for i, option in enumerate(options, 1):
            print(f"  {i:2d}. {option}")
        print()

def get_all_threats(use_pagination=True):
    """Retrieve ALL threats using pagination if needed"""
    print(f"Loading all threats...")
    
    all_threats = []
    page_number = 1
    page_size = 100  # API default page size
    
    while True:
        # Add pagination parameters (using correct API parameter names)
        params = {
            "pageNumber": page_number,
            "pageSize": page_size
        }
        
        data = make_api_request("/v1/threats", params=params)
        
        if not data or "threats" not in data:
            if page_number == 1:
                print(f"{Colors.RED}Failed to retrieve threats{Colors.RESET}")
                return []
            else:
                break  # No more pages
        
        threats = data.get("threats", [])
        total = data.get("total", 0)
        next_page = data.get("nextPageNumber")
        
        if not threats:
            break  # No more threats
        
        all_threats.extend(threats)
        print(f"Loaded page {page_number}: {len(threats)} threats (Total so far: {len(all_threats)})")
        
        # Check if we've loaded all threats or if there's no next page
        if len(all_threats) >= total or not next_page or len(threats) < page_size:
            break
        
        page_number = next_page
        
        # Safety check to prevent infinite loops
        if page_number > 100:  # Max 100 pages (10,000 threats)
            print(f"{Colors.YELLOW}Warning: Reached maximum page limit. Some threats may not be loaded.{Colors.RESET}")
            break
    
    print(f"{Colors.GREEN}Successfully loaded {len(all_threats)} total threats{Colors.RESET}")
    return all_threats

def get_threats_unlimited(limit=None, detailed=False):
    """Retrieve and display ALL threats without any API limits"""
    print(f"\n{Colors.BOLD}=== ALL Abnormal Security Threats (Unlimited) ==={Colors.RESET}\n")
    
    # Get ALL threats using pagination
    threats = get_all_threats(use_pagination=True)
    
    if not threats:
        print(f"{Colors.RED}No threats found{Colors.RESET}")
        return
    
    total = len(threats)
    print(f"Displaying {total} total threats\n")
    
    # Apply limit if specified (for display purposes only)
    display_threats = threats
    if limit and len(threats) > limit:
        display_threats = threats[:limit]
        print(f"{Colors.YELLOW}Note: Showing first {limit} threats for display. All {total} threats are available for bulk operations.{Colors.RESET}\n")
    
    # Keep track of priorities for summary
    priority_counts = {1: 0, 2: 0, 3: 0, 4: 0}
    
    # Display each threat with priority
    for idx, threat in enumerate(display_threats):
        threat_id = threat.get("threatId", "unknown")
        
        # Get detailed threat info if requested
        if detailed:
            detailed_data = make_api_request(f"/v1/threats/{threat_id}")
            if detailed_data:
                threat = detailed_data
        
        # Extract threat details
        subject = threat.get("subject", "No subject")
        received_time = threat.get("receivedTime", "Unknown time")
        attack_type = threat.get("attackType", "Unknown type")
        confidence = threat.get("confidence", "Unknown")
        
        # Determine priority
        priority = prioritize_threat(threat)
        priority_counts[priority["level"]] += 1
        
        # Format and display the threat
        print(f"{Colors.BOLD}Threat {idx+1}:{Colors.RESET} {priority['display']}")
        print(f"  ID: {threat_id}")
        print(f"  Subject: {textwrap.shorten(subject, width=60)}")
        print(f"  Type: {attack_type} ({confidence} confidence)")
        print(f"  Time: {received_time}")
        
        # Show remediation options
        print(f"  {Colors.BOLD}Actions:{Colors.RESET}")
        if priority["level"] <= 2:  # P1 or P2
            print(f"    - Remediate: ./abnormal_cli.py remediate {threat_id}")
            print(f"    - Quarantine: ./abnormal_cli.py quarantine {threat_id}")
        print(f"    - Details: ./abnormal_cli.py threat-details {threat_id}")
        print()
    
    # Display priority distribution
    display_priority_summary(priority_counts)
    
    # Show bulk operation options
    if total > 0:
        print(f"\n{Colors.BOLD}Bulk Operations Available:{Colors.RESET}")
        print(f"  • All threats: ./abnormal_cli.py bulk-interactive")
        print(f"  • By priority: ./abnormal_cli.py threats-p1 --all")
        print(f"  • By type: ./abnormal_cli.py threats-by-type 'Phishing: Credential' --all")
    
    return threats

def log_remediation_action(threat_id, action, threat_details, result, reason=None):
    """Log detailed information about remediation actions"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Extract key threat information
    subject = threat_details.get("subject", "No subject")
    attack_type = threat_details.get("attackType", "Unknown")
    confidence = threat_details.get("confidence", "Unknown")
    received_time = threat_details.get("receivedTime", "Unknown")
    sender_email = threat_details.get("sender", {}).get("email", "Unknown")
    sender_name = threat_details.get("sender", {}).get("name", "Unknown")
    
    # Create detailed log entry
    log_entry = {
        "timestamp": timestamp,
        "threat_id": threat_id,
        "action": action,
        "reason": reason,
        "threat_details": {
            "subject": subject,
            "attack_type": attack_type,
            "confidence": confidence,
            "received_time": received_time,
            "sender_email": sender_email,
            "sender_name": sender_name
        },
        "result": result,
        "success": result.get("success", False) if result else False,
        "action_id": result.get("actionId") if result else None
    }
    
    # Log to file
    logging.info(f"REMEDIATION ACTION: {json.dumps(log_entry, indent=2)}")
    
    # Also log to console with color coding
    status_color = Colors.GREEN if log_entry["success"] else Colors.RED
    status_icon = "✓" if log_entry["success"] else "✗"
    
    print(f"\n{Colors.BOLD}=== Remediation Action Log ==={Colors.RESET}")
    print(f"{Colors.CYAN}Timestamp:{Colors.RESET} {timestamp}")
    print(f"{Colors.CYAN}Threat ID:{Colors.RESET} {threat_id}")
    print(f"{Colors.CYAN}Action:{Colors.RESET} {action}")
    print(f"{Colors.CYAN}Status:{Colors.RESET} {status_color}{status_icon} {'SUCCESS' if log_entry['success'] else 'FAILED'}{Colors.RESET}")
    print(f"{Colors.CYAN}Subject:{Colors.RESET} {subject}")
    print(f"{Colors.CYAN}Attack Type:{Colors.RESET} {attack_type}")
    print(f"{Colors.CYAN}Confidence:{Colors.RESET} {confidence}")
    print(f"{Colors.CYAN}Sender:{Colors.RESET} {sender_name} ({sender_email})")
    print(f"{Colors.CYAN}Received:{Colors.RESET} {received_time}")
    if reason:
        print(f"{Colors.CYAN}Reason:{Colors.RESET} {reason}")
    if log_entry["action_id"]:
        print(f"{Colors.CYAN}Action ID:{Colors.RESET} {log_entry['action_id']}")
    print(f"{Colors.CYAN}Log File:{Colors.RESET} {remediation_log_file}")
    print(f"{Colors.BOLD}================================{Colors.RESET}\n")
    
    return log_entry

def take_action_with_logging(threat_id, action, action_data=None, reason=None):
    """Take action on a threat with comprehensive logging"""
    print(f"\n{Colors.BOLD}=== Taking Action on Threat ==={Colors.RESET}\n")
    print(f"Threat ID: {threat_id}")
    print(f"Action: {action}")
    
    # Get detailed threat information first
    print(f"Loading threat details...")
    threat_details = make_api_request(f"/v1/threats/{threat_id}")
    
    if not threat_details:
        print(f"{Colors.RED}Failed to retrieve threat details{Colors.RESET}")
        return None
    
    # Prepare action data
    data = {"action": action}
    if action_data:
        data.update(action_data)
    
    # Take the action
    result = make_api_request(f"/v1/threats/{threat_id}", method="POST", data=data)
    
    # Log the action with all details
    log_entry = log_remediation_action(threat_id, action, threat_details, result, reason)
    
    return log_entry

def bulk_remediate_threats_unlimited(threat_ids, action="remediate", reason=None, batch_size=50):
    """Perform bulk remediation on unlimited threats with batching and detailed logging"""
    print(f"\n{Colors.BOLD}=== Bulk {action.title()} Operation (Unlimited) ==={Colors.RESET}\n")
    print(f"Target threats: {len(threat_ids)}")
    print(f"Action: {action}")
    print(f"Batch size: {batch_size}")
    if reason:
        print(f"Reason: {reason}")
    print(f"Log file: {remediation_log_file}")
    print()
    
    # Confirm bulk operation
    response = input(f"{Colors.YELLOW}Are you sure you want to {action} {len(threat_ids)} threats? (yes/no): {Colors.RESET}")
    if response.lower() not in ['yes', 'y']:
        print(f"{Colors.YELLOW}Bulk operation cancelled{Colors.RESET}")
        return
    
    # Log bulk operation start
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    logging.info(f"BULK OPERATION START: {action} on {len(threat_ids)} threats at {timestamp}")
    
    results = {
        "success": [],
        "failed": [],
        "skipped": [],
        "details": []
    }
    
    # Process in batches
    total_batches = (len(threat_ids) + batch_size - 1) // batch_size
    
    for batch_num in range(total_batches):
        start_idx = batch_num * batch_size
        end_idx = min(start_idx + batch_size, len(threat_ids))
        batch_threats = threat_ids[start_idx:end_idx]
        
        print(f"\n{Colors.BOLD}Processing batch {batch_num + 1}/{total_batches} ({len(batch_threats)} threats){Colors.RESET}")
        
        for i, threat_id in enumerate(batch_threats, 1):
            global_idx = start_idx + i
            print(f"  [{global_idx}/{len(threat_ids)}] Processing: {threat_id}")
            
            try:
                # Get threat details first
                threat_details = make_api_request(f"/v1/threats/{threat_id}")
                
                if not threat_details:
                    print(f"    {Colors.RED}✗ Failed to get threat details{Colors.RESET}")
                    results["failed"].append(threat_id)
                    continue
                
                # Prepare action data
                action_data = {}
                if reason:
                    action_data["reason"] = reason
                
                # Take action
                result = make_api_request(f"/v1/threats/{threat_id}", method="POST", data={"action": action, **action_data})
                
                # Log the action
                log_entry = log_remediation_action(threat_id, action, threat_details, result, reason)
                results["details"].append(log_entry)
                
                if result and result.get("success", False):
                    results["success"].append(threat_id)
                    print(f"    {Colors.GREEN}✓ Success{Colors.RESET}")
                else:
                    results["failed"].append(threat_id)
                    print(f"    {Colors.RED}✗ Failed{Colors.RESET}")
                    
            except Exception as e:
                results["failed"].append(threat_id)
                print(f"    {Colors.RED}✗ Error: {str(e)}{Colors.RESET}")
            
            # Small delay to avoid overwhelming the API
            time.sleep(0.2)
        
        # Progress update after each batch
        print(f"\n{Colors.CYAN}Batch {batch_num + 1} complete. Progress: {global_idx}/{len(threat_ids)} ({global_idx/len(threat_ids)*100:.1f}%){Colors.RESET}")
        
        # Optional pause between batches for very large operations
        if total_batches > 5 and batch_num < total_batches - 1:
            response = input(f"{Colors.YELLOW}Continue to next batch? (yes/no/pause): {Colors.RESET}")
            if response.lower() in ['no', 'n']:
                print(f"{Colors.YELLOW}Bulk operation stopped by user{Colors.RESET}")
                break
            elif response.lower() in ['pause', 'p']:
                input(f"{Colors.YELLOW}Press Enter to continue...{Colors.RESET}")
    
    # Log bulk operation completion
    end_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    logging.info(f"BULK OPERATION COMPLETE: {action} completed at {end_timestamp}")
    logging.info(f"BULK OPERATION SUMMARY: Success={len(results['success'])}, Failed={len(results['failed'])}, Skipped={len(results['skipped'])}")
    
    # Display summary
    print(f"\n{Colors.BOLD}=== Bulk Operation Summary ==={Colors.RESET}")
    print(f"{Colors.GREEN}Successful: {len(results['success'])}{Colors.RESET}")
    print(f"{Colors.RED}Failed: {len(results['failed'])}{Colors.RESET}")
    print(f"{Colors.YELLOW}Skipped: {len(results['skipped'])}{Colors.RESET}")
    print(f"{Colors.CYAN}Log File: {remediation_log_file}{Colors.RESET}")
    
    if results["failed"]:
        print(f"\n{Colors.RED}Failed threat IDs (first 10):{Colors.RESET}")
        for threat_id in results["failed"][:10]:
            print(f"  {threat_id}")
        if len(results["failed"]) > 10:
            print(f"  ... and {len(results['failed']) - 10} more")
    
    # Show how to find the remediated threats later
    print(f"\n{Colors.BOLD}To find remediated threats later:{Colors.RESET}")
    print(f"  • Check the log file: {remediation_log_file}")
    print(f"  • Search for threat IDs: grep 'threat_id' {remediation_log_file}")
    print(f"  • Search by action: grep '{action}' {remediation_log_file}")
    print(f"  • Search by timestamp: grep '{timestamp}' {remediation_log_file}")

def show_remediation_history(limit=50):
    """Show recent remediation history from log files"""
    print(f"\n{Colors.BOLD}=== Recent Remediation History ==={Colors.RESET}\n")
    
    log_dir = "logs"
    if not os.path.exists(log_dir):
        print(f"{Colors.YELLOW}No remediation logs found{Colors.RESET}")
        return
    
    # Find all remediation log files
    log_files = [f for f in os.listdir(log_dir) if f.startswith("remediation_") and f.endswith(".log")]
    log_files.sort(reverse=True)  # Most recent first
    
    if not log_files:
        print(f"{Colors.YELLOW}No remediation logs found{Colors.RESET}")
        return
    
    print(f"Found {len(log_files)} remediation log files")
    print(f"Showing last {limit} actions from most recent logs\n")
    
    action_count = 0
    
    for log_file in log_files:
        if action_count >= limit:
            break
            
        log_path = os.path.join(log_dir, log_file)
        try:
            with open(log_path, 'r') as f:
                lines = f.readlines()
                
            # Parse log entries
            for line in lines:
                if "REMEDIATION ACTION:" in line:
                    try:
                        # Extract JSON from log line
                        json_start = line.find('{')
                        if json_start != -1:
                            json_str = line[json_start:]
                            log_entry = json.loads(json_str)
                            
                            # Display action summary
                            timestamp = log_entry.get("timestamp", "Unknown")
                            threat_id = log_entry.get("threat_id", "Unknown")
                            action = log_entry.get("action", "Unknown")
                            success = log_entry.get("success", False)
                            subject = log_entry.get("threat_details", {}).get("subject", "No subject")
                            
                            status_color = Colors.GREEN if success else Colors.RED
                            status_icon = "✓" if success else "✗"
                            
                            print(f"{Colors.CYAN}{timestamp}{Colors.RESET} {status_color}{status_icon}{Colors.RESET} {action} - {threat_id}")
                            print(f"  Subject: {textwrap.shorten(subject, width=80)}")
                            print()
                            
                            action_count += 1
                            if action_count >= limit:
                                break
                                
                    except json.JSONDecodeError:
                        continue
                        
        except Exception as e:
            print(f"{Colors.RED}Error reading log file {log_file}: {e}{Colors.RESET}")
    
    if action_count == 0:
        print(f"{Colors.YELLOW}No remediation actions found in logs{Colors.RESET}")
    else:
        print(f"{Colors.CYAN}Total actions shown: {action_count}{Colors.RESET}")
        print(f"{Colors.CYAN}For full details, check the log files in the 'logs' directory{Colors.RESET}")

def interactive_bulk_operation_unlimited():
    """Interactive mode for unlimited bulk operations"""
    print(f"\n{Colors.BOLD}=== Interactive Bulk Operations (Unlimited) ==={Colors.RESET}\n")
    
    # Get ALL threats first
    print("Loading ALL threats (this may take a moment)...")
    threats = get_all_threats(use_pagination=True)
    
    if not threats:
        print(f"{Colors.RED}No threats found{Colors.RESET}")
        return
    
    print(f"Loaded {len(threats)} threats\n")
    
    # Show filtering options
    print(f"{Colors.BOLD}Filter options:{Colors.RESET}")
    print("1. By priority level (P1, P2, P3, P4)")
    print("2. By attack type")
    print("3. By attack vector")
    print("4. By attack strategy")
    print("5. By impersonated party")
    print("6. All threats (UNLIMITED)")
    
    choice = input(f"\n{Colors.YELLOW}Select filter option (1-6): {Colors.RESET}")
    
    filtered_threats = []
    
    if choice == "1":
        priority = input(f"{Colors.YELLOW}Enter priority level (1-4): {Colors.RESET}")
        if priority.isdigit() and 1 <= int(priority) <= 4:
            filtered_threats = [t for t in threats if prioritize_threat(t)["level"] == int(priority)]
    elif choice == "2":
        print(f"\n{Colors.BOLD}Available attack types:{Colors.RESET}")
        for i, attack_type in enumerate(THREAT_CATEGORIES["attack_type"], 1):
            print(f"  {i}. {attack_type}")
        attack_choice = input(f"\n{Colors.YELLOW}Select attack type (1-{len(THREAT_CATEGORIES['attack_type'])}): {Colors.RESET}")
        if attack_choice.isdigit() and 1 <= int(attack_choice) <= len(THREAT_CATEGORIES["attack_type"]):
            selected_type = THREAT_CATEGORIES["attack_type"][int(attack_choice) - 1]
            filtered_threats = [t for t in threats if t.get("attackType", "").lower() == selected_type.lower()]
    elif choice == "6":
        filtered_threats = threats
    else:
        print(f"{Colors.RED}Option not implemented yet{Colors.RESET}")
        return
    
    if not filtered_threats:
        print(f"{Colors.YELLOW}No threats match the selected criteria{Colors.RESET}")
        return
    
    print(f"\n{Colors.GREEN}Found {len(filtered_threats)} threats to process{Colors.RESET}")
    
    # Show action options
    print(f"\n{Colors.BOLD}Action options:{Colors.RESET}")
    print("1. Remediate")
    print("2. Quarantine")
    print("3. Mark as false positive")
    
    action_choice = input(f"\n{Colors.YELLOW}Select action (1-3): {Colors.RESET}")
    
    action_map = {"1": "remediate", "2": "quarantine", "3": "mark_false_positive"}
    if action_choice not in action_map:
        print(f"{Colors.RED}Invalid action choice{Colors.RESET}")
        return
    
    action = action_map[action_choice]
    reason = input(f"\n{Colors.YELLOW}Reason for bulk action (optional): {Colors.RESET}")
    
    # Batch size selection for large operations
    if len(filtered_threats) > 100:
        print(f"\n{Colors.BOLD}Large operation detected ({len(filtered_threats)} threats){Colors.RESET}")
        batch_size = input(f"{Colors.YELLOW}Enter batch size (default 50, max 100): {Colors.RESET}")
        try:
            batch_size = int(batch_size) if batch_size.strip() else 50
            batch_size = min(max(batch_size, 1), 100)  # Between 1 and 100
        except ValueError:
            batch_size = 50
    else:
        batch_size = 50
    
    # Extract threat IDs
    threat_ids = [t.get("threatId") for t in filtered_threats if t.get("threatId")]
    
    # Perform unlimited bulk operation
    bulk_remediate_threats_unlimited(threat_ids, action, reason, batch_size)

def get_threats_by_priority(priority_level, limit=None):
    """Retrieve and display threats by priority level (P1, P2, P3, P4)"""
    print(f"\n{Colors.BOLD}=== Threats by Priority Level ==={Colors.RESET}\n")
    
    # Get all threats
    params = {}
    data = make_api_request("/v1/threats", params=params)
    
    if not data or "threats" not in data:
        print(f"{Colors.RED}Failed to retrieve threats{Colors.RESET}")
        return []
    
    threats = data.get("threats", [])
    total = data.get("total", 0)
    
    # Filter threats by priority
    priority_threats = []
    for threat in threats:
        priority = prioritize_threat(threat)
        if priority["level"] == priority_level:
            priority_threats.append(threat)
    
    priority_labels = {1: "P1 (Critical)", 2: "P2 (High)", 3: "P3 (Medium)", 4: "P4 (Low)"}
    print(f"Found {len(priority_threats)} {priority_labels[priority_level]} threats out of {total} total threats\n")
    
    # Apply limit if specified
    if limit and len(priority_threats) > limit:
        priority_threats = priority_threats[:limit]
        print(f"Showing first {limit} threats (use --all to see all)\n")
    
    # Display priority threats
    for idx, threat in enumerate(priority_threats):
        threat_id = threat.get("threatId", "unknown")
        subject = threat.get("subject", "No subject")
        received_time = threat.get("receivedTime", "Unknown time")
        attack_type = threat.get("attackType", "Unknown type")
        
        print(f"{Colors.BOLD}Threat {idx+1}:{Colors.RESET}")
        print(f"  ID: {threat_id}")
        print(f"  Subject: {textwrap.shorten(subject, width=60)}")
        print(f"  Type: {attack_type}")
        print(f"  Time: {received_time}")
        print(f"  {Colors.BOLD}Actions:{Colors.RESET}")
        print(f"    - Remediate: ./abnormal_cli.py remediate {threat_id}")
        print(f"    - Quarantine: ./abnormal_cli.py quarantine {threat_id}")
        print(f"    - Details: ./abnormal_cli.py threat-details {threat_id}")
        print()
    
    return priority_threats

def interactive_bulk_operation():
    """Interactive mode for bulk operations"""
    print(f"\n{Colors.BOLD}=== Interactive Bulk Operations ==={Colors.RESET}\n")
    
    # Get all threats first
    print("Loading all threats...")
    params = {}
    data = make_api_request("/v1/threats", params=params)
    
    if not data or "threats" not in data:
        print(f"{Colors.RED}Failed to retrieve threats{Colors.RESET}")
        return
    
    threats = data.get("threats", [])
    print(f"Loaded {len(threats)} threats\n")
    
    # Show filtering options
    print(f"{Colors.BOLD}Filter options:{Colors.RESET}")
    print("1. By priority level (P1, P2, P3, P4)")
    print("2. By attack type")
    print("3. By attack vector")
    print("4. By attack strategy")
    print("5. By impersonated party")
    print("6. All threats")
    
    choice = input(f"\n{Colors.YELLOW}Select filter option (1-6): {Colors.RESET}")
    
    filtered_threats = []
    
    if choice == "1":
        priority = input(f"{Colors.YELLOW}Enter priority level (1-4): {Colors.RESET}")
        if priority.isdigit() and 1 <= int(priority) <= 4:
            filtered_threats = [t for t in threats if prioritize_threat(t)["level"] == int(priority)]
    elif choice == "2":
        print(f"\n{Colors.BOLD}Available attack types:{Colors.RESET}")
        for i, attack_type in enumerate(THREAT_CATEGORIES["attack_type"], 1):
            print(f"  {i}. {attack_type}")
        attack_choice = input(f"\n{Colors.YELLOW}Select attack type (1-{len(THREAT_CATEGORIES['attack_type'])}): {Colors.RESET}")
        if attack_choice.isdigit() and 1 <= int(attack_choice) <= len(THREAT_CATEGORIES["attack_type"]):
            selected_type = THREAT_CATEGORIES["attack_type"][int(attack_choice) - 1]
            filtered_threats = [t for t in threats if t.get("attackType", "").lower() == selected_type.lower()]
    elif choice == "6":
        filtered_threats = threats
    else:
        print(f"{Colors.RED}Option not implemented yet{Colors.RESET}")
        return
    
    if not filtered_threats:
        print(f"{Colors.YELLOW}No threats match the selected criteria{Colors.RESET}")
        return
    
    print(f"\n{Colors.GREEN}Found {len(filtered_threats)} threats to process{Colors.RESET}")
    
    # Show action options
    print(f"\n{Colors.BOLD}Action options:{Colors.RESET}")
    print("1. Remediate")
    print("2. Quarantine")
    print("3. Mark as false positive")
    
    action_choice = input(f"\n{Colors.YELLOW}Select action (1-3): {Colors.RESET}")
    
    action_map = {"1": "remediate", "2": "quarantine", "3": "mark_false_positive"}
    if action_choice not in action_map:
        print(f"{Colors.RED}Invalid action choice{Colors.RESET}")
        return
    
    action = action_map[action_choice]
    reason = input(f"\n{Colors.YELLOW}Reason for bulk action (optional): {Colors.RESET}")
    
    # Extract threat IDs
    threat_ids = [t.get("threatId") for t in filtered_threats if t.get("threatId")]
    
    # Perform bulk operation
    bulk_remediate_threats(threat_ids, action, reason)

def main():
    """Main function to parse arguments and execute commands"""
    parser = argparse.ArgumentParser(description="Abnormal Security CLI Tool", add_help=False)
    parser.add_argument("command", nargs="?", default="help", help="Command to execute")
    parser.add_argument("arg1", nargs="?", help="First argument")
    parser.add_argument("arg2", nargs="?", help="Second argument")
    
    args = parser.parse_args()
    
    if args.command == "test":
        test_endpoints()
    elif args.command == "threats":
        limit = int(args.arg1) if args.arg1 and args.arg1.isdigit() else 10
        get_threats(limit)
    elif args.command == "threats-detailed":
        limit = int(args.arg1) if args.arg1 and args.arg1.isdigit() else 10
        get_threats(limit, detailed=True)
    elif args.command == "threats-unlimited":
        limit = int(args.arg1) if args.arg1 and args.arg1.isdigit() else None
        get_threats_unlimited(limit, detailed=False)
    elif args.command == "threat-details":
        if not args.arg1:
            print(f"{Colors.RED}Error: Threat ID is required{Colors.RESET}")
            sys.exit(1)
        get_threat_details(args.arg1)
    elif args.command == "remediate":
        if not args.arg1:
            print(f"{Colors.RED}Error: Threat ID is required{Colors.RESET}")
            sys.exit(1)
        take_action(args.arg1, "remediate")
    elif args.command == "quarantine":
        if not args.arg1:
            print(f"{Colors.RED}Error: Threat ID is required{Colors.RESET}")
            sys.exit(1)
        take_action(args.arg1, "quarantine")
    elif args.command == "mark-fp":
        if not args.arg1:
            print(f"{Colors.RED}Error: Threat ID is required{Colors.RESET}")
            sys.exit(1)
        take_action(args.arg1, "mark_false_positive", {"reason": "Identified as legitimate via CLI tool"})
    elif args.command == "action-status":
        if not args.arg1 or not args.arg2:
            print(f"{Colors.RED}Error: Threat ID and Action ID are required{Colors.RESET}")
            sys.exit(1)
        get_action_status(args.arg1, args.arg2)
    elif args.command == "dashboard":
        get_dashboard_summary()
    elif args.command == "categories":
        list_categories()
    elif args.command == "threats-by-type":
        if not args.arg1:
            print(f"{Colors.RED}Error: Attack type is required{Colors.RESET}")
            print(f"Use './abnormal_cli.py categories' to see available types")
            sys.exit(1)
        limit = int(args.arg2) if args.arg2 and args.arg2.isdigit() else None
        get_threats_by_category("attack_type", args.arg1, limit)
    elif args.command == "threats-by-vector":
        if not args.arg1:
            print(f"{Colors.RED}Error: Attack vector is required{Colors.RESET}")
            print(f"Use './abnormal_cli.py categories' to see available vectors")
            sys.exit(1)
        limit = int(args.arg2) if args.arg2 and args.arg2.isdigit() else None
        get_threats_by_category("attack_vector", args.arg1, limit)
    elif args.command == "threats-by-strategy":
        if not args.arg1:
            print(f"{Colors.RED}Error: Attack strategy is required{Colors.RESET}")
            print(f"Use './abnormal_cli.py categories' to see available strategies")
            sys.exit(1)
        limit = int(args.arg2) if args.arg2 and args.arg2.isdigit() else None
        get_threats_by_category("attack_strategy", args.arg1, limit)
    elif args.command == "threats-by-party":
        if not args.arg1:
            print(f"{Colors.RED}Error: Impersonated party is required{Colors.RESET}")
            print(f"Use './abnormal_cli.py categories' to see available parties")
            sys.exit(1)
        limit = int(args.arg2) if args.arg2 and args.arg2.isdigit() else None
        get_threats_by_category("impersonated_party", args.arg1, limit)
    elif args.command == "threats-p1":
        limit = int(args.arg1) if args.arg1 and args.arg1.isdigit() else None
        get_threats_by_priority(1, limit)
    elif args.command == "threats-p2":
        limit = int(args.arg1) if args.arg1 and args.arg1.isdigit() else None
        get_threats_by_priority(2, limit)
    elif args.command == "threats-p3":
        limit = int(args.arg1) if args.arg1 and args.arg1.isdigit() else None
        get_threats_by_priority(3, limit)
    elif args.command == "threats-p4":
        limit = int(args.arg1) if args.arg1 and args.arg1.isdigit() else None
        get_threats_by_priority(4, limit)
    elif args.command == "bulk-interactive":
        interactive_bulk_operation()
    elif args.command == "bulk-interactive-unlimited":
        interactive_bulk_operation_unlimited()
    elif args.command == "remediation-history":
        limit = int(args.arg1) if args.arg1 and args.arg1.isdigit() else 50
        show_remediation_history(limit)
    elif args.command == "false-positive-management":
        interactive_false_positive_management()
    elif args.command == "help" or args.command == "--help":
        show_help()
    else:
        print(f"{Colors.RED}Unknown command: {args.command}{Colors.RESET}")
        show_help()
        sys.exit(1)

def analyze_false_positive_patterns():
    """Analyze patterns in false positive threats to improve detection"""
    print(f"\n{Colors.BOLD}=== False Positive Pattern Analysis ==={Colors.RESET}\n")
    
    # First try to get data from Detection360 API
    api_false_positives = get_detection360_false_positives()
    
    # Also get data from local logs
    log_false_positives = get_false_positives_from_logs()
    
    # Combine both sources
    all_false_positives = api_false_positives + log_false_positives
    
    if not all_false_positives:
        print(f"{Colors.YELLOW}No false positives found in API or logs{Colors.RESET}")
        print(f"{Colors.CYAN}Would you like to create test data for demonstration? (y/n): {Colors.RESET}")
        choice = input().lower().strip()
        if choice == 'y':
            if create_test_false_positive_data():
                # Retry analysis with new test data
                log_false_positives = get_false_positives_from_logs()
                all_false_positives = api_false_positives + log_false_positives
            else:
                return
        else:
            return
    
    print(f"Found {len(all_false_positives)} false positive actions\n")
    
    # Analyze patterns
    patterns = {
        "attack_types": {},
        "senders": {},
        "subjects": {},
        "confidence_levels": {},
        "time_periods": {},
        "reasons": {}
    }
    
    for fp in all_false_positives:
        # Handle both API and log formats
        if isinstance(fp, dict):
            if "threat_details" in fp:
                # Log format
                details = fp.get("threat_details", {})
                reason = fp.get("reason", "No reason")
            else:
                # API format - Detection360Case
                details = fp.get("report", {}).get("analysis", {})
                reason = "API reported"
            
            # Attack type patterns
            attack_type = details.get("attack_type", "Unknown")
            patterns["attack_types"][attack_type] = patterns["attack_types"].get(attack_type, 0) + 1
            
            # Sender patterns
            sender_email = details.get("sender_email", "Unknown")
            sender_domain = sender_email.split('@')[-1] if '@' in sender_email else "Unknown"
            patterns["senders"][sender_domain] = patterns["senders"].get(sender_domain, 0) + 1
            
            # Subject patterns
            subject = details.get("subject", "No subject").lower()
            # Extract common words
            words = [word for word in subject.split() if len(word) > 3]
            for word in words[:5]:  # Limit to first 5 words
                patterns["subjects"][word] = patterns["subjects"].get(word, 0) + 1
            
            # Confidence patterns
            confidence = details.get("confidence", "Unknown")
            patterns["confidence_levels"][confidence] = patterns["confidence_levels"].get(confidence, 0) + 1
            
            # Reason patterns
            patterns["reasons"][reason] = patterns["reasons"].get(reason, 0) + 1
            
            # Time patterns
            received_time = details.get("received_time", "Unknown")
            if received_time != "Unknown":
                try:
                    # Extract hour from timestamp
                    hour = received_time.split('T')[1].split(':')[0]
                    patterns["time_periods"][hour] = patterns["time_periods"].get(hour, 0) + 1
                except:
                    pass
    
    # Display pattern analysis
    print(f"{Colors.BOLD}False Positive Patterns:{Colors.RESET}\n")
    
    # Attack type patterns
    print(f"{Colors.CYAN}Most Common Attack Types:{Colors.RESET}")
    sorted_attack_types = sorted(patterns["attack_types"].items(), key=lambda x: x[1], reverse=True)
    for attack_type, count in sorted_attack_types[:5]:
        percentage = (count / len(all_false_positives)) * 100
        print(f"  {attack_type}: {count} ({percentage:.1f}%)")
    
    # Sender domain patterns
    print(f"\n{Colors.CYAN}Most Common Sender Domains:{Colors.RESET}")
    sorted_senders = sorted(patterns["senders"].items(), key=lambda x: x[1], reverse=True)
    for domain, count in sorted_senders[:5]:
        percentage = (count / len(all_false_positives)) * 100
        print(f"  {domain}: {count} ({percentage:.1f}%)")
    
    # Subject word patterns
    print(f"\n{Colors.CYAN}Most Common Subject Words:{Colors.RESET}")
    sorted_words = sorted(patterns["subjects"].items(), key=lambda x: x[1], reverse=True)
    for word, count in sorted_words[:10]:
        percentage = (count / len(all_false_positives)) * 100
        print(f"  '{word}': {count} ({percentage:.1f}%)")
    
    # Confidence patterns
    print(f"\n{Colors.CYAN}Confidence Level Distribution:{Colors.RESET}")
    for confidence, count in patterns["confidence_levels"].items():
        percentage = (count / len(all_false_positives)) * 100
        print(f"  {confidence}: {count} ({percentage:.1f}%)")
    
    # Reason patterns
    print(f"\n{Colors.CYAN}Most Common Reasons:{Colors.RESET}")
    sorted_reasons = sorted(patterns["reasons"].items(), key=lambda x: x[1], reverse=True)
    for reason, count in sorted_reasons[:5]:
        percentage = (count / len(all_false_positives)) * 100
        print(f"  {reason}: {count} ({percentage:.1f}%)")
    
    # Time patterns
    if patterns["time_periods"]:
        print(f"\n{Colors.CYAN}Time Period Distribution (Hour of Day):{Colors.RESET}")
        sorted_times = sorted(patterns["time_periods"].items(), key=lambda x: int(x[0]))
        for hour, count in sorted_times:
            percentage = (count / len(all_false_positives)) * 100
            print(f"  {hour}:00: {count} ({percentage:.1f}%)")
    
    # Recommendations
    print(f"\n{Colors.BOLD}Recommendations:{Colors.RESET}")
    if sorted_attack_types and sorted_attack_types[0][1] > len(all_false_positives) * 0.3:
        print(f"• {Colors.YELLOW}Consider adjusting detection rules for '{sorted_attack_types[0][0]}' attacks{Colors.RESET}")
    
    if sorted_senders and sorted_senders[0][1] > len(all_false_positives) * 0.2:
        print(f"• {Colors.YELLOW}Review whitelist for domain '{sorted_senders[0][0]}'{Colors.RESET}")
    
    if sorted_words and sorted_words[0][1] > len(all_false_positives) * 0.4:
        print(f"• {Colors.YELLOW}Consider keyword filtering for '{sorted_words[0][0]}'{Colors.RESET}")

def get_false_positives_from_logs():
    """Get false positive data from local log files"""
    log_dir = "logs"
    if not os.path.exists(log_dir):
        return []
    
    # Find all remediation log files
    log_files = [f for f in os.listdir(log_dir) if f.startswith("remediation_") and f.endswith(".log")]
    
    if not log_files:
        return []
    
    false_positives = []
    
    # Parse all log files for false positive actions
    for log_file in log_files:
        log_path = os.path.join(log_dir, log_file)
        try:
            with open(log_path, 'r') as f:
                lines = f.readlines()
                
            for line in lines:
                if "REMEDIATION ACTION:" in line and "mark_false_positive" in line:
                    try:
                        json_start = line.find('{')
                        if json_start != -1:
                            json_str = line[json_start:]
                            log_entry = json.loads(json_str)
                            false_positives.append(log_entry)
                    except json.JSONDecodeError:
                        continue
                        
        except Exception as e:
            print(f"{Colors.RED}Error reading log file {log_file}: {e}{Colors.RESET}")
    
    return false_positives

def get_detection360_false_positives(start_date=None, end_date=None, status=None):
    """Fetch false positive reports from Detection360 API"""
    print(f"\n{Colors.BOLD}=== Fetching False Positive Reports from Detection360 ==={Colors.RESET}\n")
    
    # Build query parameters
    params = {
        "inquiry_type": "FALSE_POSITIVE"
    }
    
    if start_date:
        params["start"] = start_date
    if end_date:
        params["end"] = end_date
    if status:
        if isinstance(status, list):
            params["status"] = status
        else:
            params["status"] = [status]
    
    try:
        response = make_api_request("/detection360/reports", method="GET", params=params)
        
        if response and isinstance(response, list):
            print(f"{Colors.GREEN}Successfully retrieved {len(response)} false positive reports{Colors.RESET}\n")
            return response
        else:
            print(f"{Colors.YELLOW}No false positive reports found or invalid response{Colors.RESET}")
            return []
            
    except Exception as e:
        print(f"{Colors.RED}Error fetching false positive reports: {e}{Colors.RESET}")
        return []

def submit_false_positive_report(portal_link, received_date, description=None):
    """Submit a false positive report to Detection360 API"""
    print(f"\n{Colors.BOLD}=== Submitting False Positive Report ==={Colors.RESET}\n")
    
    # Build the request payload
    payload = {
        "report_type": "false-positive",
        "portal_link": portal_link,
        "received_date": received_date
    }
    
    if description:
        payload["description"] = description
    
    try:
        response = make_api_request("/detection360/reports", method="POST", data=payload)
        
        if response:
            print(f"{Colors.GREEN}False positive report submitted successfully{Colors.RESET}")
            return True
        else:
            print(f"{Colors.YELLOW}Failed to submit false positive report{Colors.RESET}")
            return False
            
    except Exception as e:
        print(f"{Colors.RED}Error submitting false positive report: {e}{Colors.RESET}")
        return False

def create_test_false_positive_data():
    """Create test false positive data for demonstration purposes"""
    print(f"\n{Colors.BOLD}=== Creating Test False Positive Data ==={Colors.RESET}\n")
    
    # Create logs directory if it doesn't exist
    log_dir = "logs"
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    # Create a test log file with false positive entries
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = os.path.join(log_dir, f"remediation_{timestamp}.log")
    
    # Sample false positive data
    test_false_positives = [
        {
            "timestamp": "2024-01-15T10:30:00Z",
            "threat_id": "test-fp-001",
            "action": "mark_false_positive",
            "reason": "Legitimate marketing email from known vendor",
            "success": True,
            "action_id": "act-001",
            "threat_details": {
                "subject": "Your Monthly Newsletter - January 2024",
                "attack_type": "Phishing: Credential",
                "confidence": "Medium",
                "sender_email": "newsletter@legitimate-vendor.com",
                "sender_name": "Legitimate Vendor Inc",
                "received_time": "2024-01-15T10:25:00Z"
            }
        },
        {
            "timestamp": "2024-01-14T14:15:00Z",
            "threat_id": "test-fp-002",
            "action": "mark_false_positive",
            "reason": "Internal communication flagged incorrectly",
            "success": True,
            "action_id": "act-002",
            "threat_details": {
                "subject": "Team Meeting - Q1 Planning",
                "attack_type": "Business Email Compromise",
                "confidence": "High",
                "sender_email": "manager@company.com",
                "sender_name": "John Manager",
                "received_time": "2024-01-14T14:10:00Z"
            }
        },
        {
            "timestamp": "2024-01-13T09:45:00Z",
            "threat_id": "test-fp-003",
            "action": "mark_false_positive",
            "reason": "False positive - legitimate invoice",
            "success": True,
            "action_id": "act-003",
            "threat_details": {
                "subject": "Invoice #INV-2024-001 - Payment Due",
                "attack_type": "Invoice Fraud",
                "confidence": "Medium",
                "sender_email": "billing@trusted-supplier.com",
                "sender_name": "Trusted Supplier LLC",
                "received_time": "2024-01-13T09:40:00Z"
            }
        },
        {
            "timestamp": "2024-01-12T16:20:00Z",
            "threat_id": "test-fp-004",
            "action": "mark_false_positive",
            "reason": "Legitimate password reset request",
            "success": True,
            "action_id": "act-004",
            "threat_details": {
                "subject": "Password Reset Request - Action Required",
                "attack_type": "Phishing: Credential",
                "confidence": "High",
                "sender_email": "security@company-portal.com",
                "sender_name": "Company Portal Security",
                "received_time": "2024-01-12T16:15:00Z"
            }
        },
        {
            "timestamp": "2024-01-11T11:30:00Z",
            "threat_id": "test-fp-005",
            "action": "mark_false_positive",
            "reason": "False positive - legitimate conference invitation",
            "success": True,
            "action_id": "act-005",
            "threat_details": {
                "subject": "Invitation: Annual Tech Conference 2024",
                "attack_type": "Business Email Compromise",
                "confidence": "Medium",
                "sender_email": "events@tech-conference.org",
                "sender_name": "Tech Conference Organizers",
                "received_time": "2024-01-11T11:25:00Z"
            }
        }
    ]
    
    try:
        with open(log_file, 'w') as f:
            for fp in test_false_positives:
                log_entry = f"REMEDIATION ACTION: {json.dumps(fp)}\n"
                f.write(log_entry)
        
        print(f"{Colors.GREEN}Created test false positive data with {len(test_false_positives)} entries{Colors.RESET}")
        print(f"Test data saved to: {log_file}")
        
        return True
        
    except Exception as e:
        print(f"{Colors.RED}Error creating test data: {e}{Colors.RESET}")
        return False

def interactive_false_positive_management():
    """Interactive false positive management interface"""
    print(f"\n{Colors.BOLD}=== False Positive Management ==={Colors.RESET}\n")
    
    while True:
        print(f"{Colors.BOLD}Available Actions:{Colors.RESET}")
        print("1. Analyze false positive patterns")
        print("2. Generate false positive report")
        print("3. View recent false positives")
        print("4. Search false positives by criteria")
        print("5. Export false positive data")
        print("6. Fetch false positives from Detection360 API")
        print("7. Submit false positive report to API")
        print("8. Create test false positive data")
        print("9. Back to main menu")
        
        choice = input(f"\n{Colors.YELLOW}Select action (1-9): {Colors.RESET}")
        
        if choice == "1":
            analyze_false_positive_patterns()
        elif choice == "2":
            output_file = input(f"{Colors.YELLOW}Output file name (optional, press Enter for default): {Colors.RESET}")
            if not output_file.strip():
                output_file = None
            generate_false_positive_report(output_file)
        elif choice == "3":
            limit = input(f"{Colors.YELLOW}Number of recent false positives to show (default 20): {Colors.RESET}")
            try:
                limit = int(limit) if limit.strip() else 20
            except ValueError:
                limit = 20
            show_recent_false_positives(limit)
        elif choice == "4":
            search_false_positives()
        elif choice == "5":
            export_false_positive_data()
        elif choice == "6":
            start_date = input(f"{Colors.YELLOW}Start date (YYYY-MM-DD, optional): {Colors.RESET}")
            end_date = input(f"{Colors.YELLOW}End date (YYYY-MM-DD, optional): {Colors.RESET}")
            status = input(f"{Colors.YELLOW}Status filter (optional): {Colors.RESET}")
            
            start = f"{start_date}T00:00:00Z" if start_date else None
            end = f"{end_date}T23:59:59Z" if end_date else None
            status_filter = status if status else None
            
            get_detection360_false_positives(start, end, status_filter)
        elif choice == "7":
            portal_link = input(f"{Colors.YELLOW}Portal link: {Colors.RESET}")
            received_date = input(f"{Colors.YELLOW}Received date (YYYY-MM-DD): {Colors.RESET}")
            description = input(f"{Colors.YELLOW}Description (optional): {Colors.RESET}")
            
            if not description.strip():
                description = None
            
            submit_false_positive_report(portal_link, received_date, description)
        elif choice == "8":
            create_test_false_positive_data()
        elif choice == "9":
            break
        else:
            print(f"{Colors.RED}Invalid choice{Colors.RESET}")
        
        input(f"\n{Colors.YELLOW}Press Enter to continue...{Colors.RESET}")

def show_recent_false_positives(limit=20):
    """Show recent false positive actions"""
    print(f"\n{Colors.BOLD}=== Recent False Positives ==={Colors.RESET}\n")
    
    log_dir = "logs"
    if not os.path.exists(log_dir):
        print(f"{Colors.YELLOW}No remediation logs found{Colors.RESET}")
        return
    
    log_files = [f for f in os.listdir(log_dir) if f.startswith("remediation_") and f.endswith(".log")]
    log_files.sort(reverse=True)  # Most recent first
    
    if not log_files:
        print(f"{Colors.YELLOW}No remediation logs found{Colors.RESET}")
        return
    
    false_positives = []
    
    # Parse log files for false positive actions
    for log_file in log_files:
        if len(false_positives) >= limit:
            break
            
        log_path = os.path.join(log_dir, log_file)
        try:
            with open(log_path, 'r') as f:
                lines = f.readlines()
                
            for line in lines:
                if "REMEDIATION ACTION:" in line and "mark_false_positive" in line:
                    try:
                        json_start = line.find('{')
                        if json_start != -1:
                            json_str = line[json_start:]
                            log_entry = json.loads(json_str)
                            false_positives.append(log_entry)
                            
                            if len(false_positives) >= limit:
                                break
                    except json.JSONDecodeError:
                        continue
                        
        except Exception as e:
            print(f"{Colors.RED}Error reading log file {log_file}: {e}{Colors.RESET}")
    
    if not false_positives:
        print(f"{Colors.YELLOW}No false positives found{Colors.RESET}")
        return
    
    print(f"Showing {len(false_positives)} recent false positives:\n")
    
    for i, fp in enumerate(false_positives, 1):
        details = fp.get("threat_details", {})
        timestamp = fp.get("timestamp", "Unknown")
        threat_id = fp.get("threat_id", "Unknown")
        subject = details.get("subject", "No subject")
        attack_type = details.get("attack_type", "Unknown")
        sender_email = details.get("sender_email", "Unknown")
        reason = fp.get("reason", "No reason provided")
        
        print(f"{Colors.BOLD}{i}.{Colors.RESET} {Colors.CYAN}{timestamp}{Colors.RESET}")
        print(f"   Threat ID: {threat_id}")
        print(f"   Subject: {textwrap.shorten(subject, width=60)}")
        print(f"   Attack Type: {attack_type}")
        print(f"   Sender: {sender_email}")
        print(f"   Reason: {reason}")
        print()

def search_false_positives():
    """Search false positives by various criteria"""
    print(f"\n{Colors.BOLD}=== Search False Positives ==={Colors.RESET}\n")
    
    print(f"{Colors.BOLD}Search Criteria:{Colors.RESET}")
    print("1. By threat ID")
    print("2. By sender email/domain")
    print("3. By attack type")
    print("4. By date range")
    print("5. By subject keywords")
    
    choice = input(f"\n{Colors.YELLOW}Select search type (1-5): {Colors.RESET}")
    
    if choice == "1":
        threat_id = input(f"{Colors.YELLOW}Enter threat ID: {Colors.RESET}")
        search_false_positives_by_criteria("threat_id", threat_id)
    elif choice == "2":
        sender = input(f"{Colors.YELLOW}Enter sender email or domain: {Colors.RESET}")
        search_false_positives_by_criteria("sender", sender)
    elif choice == "3":
        attack_type = input(f"{Colors.YELLOW}Enter attack type: {Colors.RESET}")
        search_false_positives_by_criteria("attack_type", attack_type)
    elif choice == "4":
        start_date = input(f"{Colors.YELLOW}Enter start date (YYYY-MM-DD): {Colors.RESET}")
        end_date = input(f"{Colors.YELLOW}Enter end date (YYYY-MM-DD): {Colors.RESET}")
        search_false_positives_by_date_range(start_date, end_date)
    elif choice == "5":
        keyword = input(f"{Colors.YELLOW}Enter subject keyword: {Colors.RESET}")
        search_false_positives_by_criteria("subject", keyword)
    else:
        print(f"{Colors.RED}Invalid choice{Colors.RESET}")

def search_false_positives_by_criteria(criteria_type, search_term):
    """Search false positives by specific criteria"""
    print(f"\n{Colors.BOLD}=== Searching False Positives ==={Colors.RESET}\n")
    print(f"Searching for: {search_term}")
    
    log_dir = "logs"
    if not os.path.exists(log_dir):
        print(f"{Colors.YELLOW}No remediation logs found{Colors.RESET}")
        return
    
    log_files = [f for f in os.listdir(log_dir) if f.startswith("remediation_") and f.endswith(".log")]
    
    if not log_files:
        print(f"{Colors.YELLOW}No remediation logs found{Colors.RESET}")
        return
    
    found_fps = []
    
    # Parse all log files for false positive actions
    for log_file in log_files:
        log_path = os.path.join(log_dir, log_file)
        try:
            with open(log_path, 'r') as f:
                lines = f.readlines()
                
            for line in lines:
                if "REMEDIATION ACTION:" in line and "mark_false_positive" in line:
                    try:
                        json_start = line.find('{')
                        if json_start != -1:
                            json_str = line[json_start:]
                            log_entry = json.loads(json_str)
                            
                            # Check if it matches search criteria
                            if criteria_type == "threat_id" and search_term.lower() in log_entry.get("threat_id", "").lower():
                                found_fps.append(log_entry)
                            elif criteria_type == "sender" and search_term.lower() in log_entry.get("threat_details", {}).get("sender_email", "").lower():
                                found_fps.append(log_entry)
                            elif criteria_type == "attack_type" and search_term.lower() in log_entry.get("threat_details", {}).get("attack_type", "").lower():
                                found_fps.append(log_entry)
                            elif criteria_type == "subject" and search_term.lower() in log_entry.get("threat_details", {}).get("subject", "").lower():
                                found_fps.append(log_entry)
                                
                    except json.JSONDecodeError:
                        continue
                        
        except Exception as e:
            print(f"{Colors.RED}Error reading log file {log_file}: {e}{Colors.RESET}")
    
    if not found_fps:
        print(f"{Colors.YELLOW}No false positives found matching criteria{Colors.RESET}")
        return
    
    print(f"\n{Colors.GREEN}Found {len(found_fps)} false positives{Colors.RESET}\n")
    
    for i, fp in enumerate(found_fps, 1):
        details = fp.get("threat_details", {})
        timestamp = fp.get("timestamp", "Unknown")
        threat_id = fp.get("threat_id", "Unknown")
        subject = details.get("subject", "No subject")
        attack_type = details.get("attack_type", "Unknown")
        sender_email = details.get("sender_email", "Unknown")
        
        print(f"{Colors.BOLD}{i}.{Colors.RESET} {Colors.CYAN}{timestamp}{Colors.RESET}")
        print(f"   Threat ID: {threat_id}")
        print(f"   Subject: {textwrap.shorten(subject, width=60)}")
        print(f"   Attack Type: {attack_type}")
        print(f"   Sender: {sender_email}")
        print()

def search_false_positives_by_date_range(start_date, end_date):
    """Search false positives by date range"""
    print(f"\n{Colors.BOLD}=== Searching False Positives by Date Range ==={Colors.RESET}\n")
    print(f"Date range: {start_date} to {end_date}")
    
    log_dir = "logs"
    if not os.path.exists(log_dir):
        print(f"{Colors.YELLOW}No remediation logs found{Colors.RESET}")
        return
    
    log_files = [f for f in os.listdir(log_dir) if f.startswith("remediation_") and f.endswith(".log")]
    
    if not log_files:
        print(f"{Colors.YELLOW}No remediation logs found{Colors.RESET}")
        return
    
    found_fps = []
    
    # Parse all log files for false positive actions
    for log_file in log_files:
        log_path = os.path.join(log_dir, log_file)
        try:
            with open(log_path, 'r') as f:
                lines = f.readlines()
                
            for line in lines:
                if "REMEDIATION ACTION:" in line and "mark_false_positive" in line:
                    try:
                        json_start = line.find('{')
                        if json_start != -1:
                            json_str = line[json_start:]
                            log_entry = json.loads(json_str)
                            
                            # Check if timestamp is within date range
                            timestamp = log_entry.get("timestamp", "")
                            if timestamp and start_date <= timestamp[:10] <= end_date:
                                found_fps.append(log_entry)
                                
                    except json.JSONDecodeError:
                        continue
                        
        except Exception as e:
            print(f"{Colors.RED}Error reading log file {log_file}: {e}{Colors.RESET}")
    
    if not found_fps:
        print(f"{Colors.YELLOW}No false positives found in date range{Colors.RESET}")
        return
    
    print(f"\n{Colors.GREEN}Found {len(found_fps)} false positives in date range{Colors.RESET}\n")
    
    for i, fp in enumerate(found_fps, 1):
        details = fp.get("threat_details", {})
        timestamp = fp.get("timestamp", "Unknown")
        threat_id = fp.get("threat_id", "Unknown")
        subject = details.get("subject", "No subject")
        attack_type = details.get("attack_type", "Unknown")
        sender_email = details.get("sender_email", "Unknown")
        
        print(f"{Colors.BOLD}{i}.{Colors.RESET} {Colors.CYAN}{timestamp}{Colors.RESET}")
        print(f"   Threat ID: {threat_id}")
        print(f"   Subject: {textwrap.shorten(subject, width=60)}")
        print(f"   Attack Type: {attack_type}")
        print(f"   Sender: {sender_email}")
        print()

def export_false_positive_data():
    """Export false positive data to various formats"""
    print(f"\n{Colors.BOLD}=== Export False Positive Data ==={Colors.RESET}\n")
    
    print(f"{Colors.BOLD}Export Formats:{Colors.RESET}")
    print("1. JSON (detailed)")
    print("2. CSV (spreadsheet)")
    print("3. Summary report (text)")
    
    choice = input(f"\n{Colors.YELLOW}Select export format (1-3): {Colors.RESET}")
    
    if choice == "1":
        export_false_positives_json()
    elif choice == "2":
        export_false_positives_csv()
    elif choice == "3":
        export_false_positives_summary()
    else:
        print(f"{Colors.RED}Invalid choice{Colors.RESET}")

def export_false_positives_json():
    """Export false positives to JSON format"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"false_positives_export_{timestamp}.json"
    
    # Get all false positives
    log_dir = "logs"
    if not os.path.exists(log_dir):
        print(f"{Colors.YELLOW}No remediation logs found{Colors.RESET}")
        return
    
    log_files = [f for f in os.listdir(log_dir) if f.startswith("remediation_") and f.endswith(".log")]
    
    if not log_files:
        print(f"{Colors.YELLOW}No remediation logs found{Colors.RESET}")
        return
    
    false_positives = []
    
    # Parse all log files for false positive actions
    for log_file in log_files:
        log_path = os.path.join(log_dir, log_file)
        try:
            with open(log_path, 'r') as f:
                lines = f.readlines()
                
            for line in lines:
                if "REMEDIATION ACTION:" in line and "mark_false_positive" in line:
                    try:
                        json_start = line.find('{')
                        if json_start != -1:
                            json_str = line[json_start:]
                            log_entry = json.loads(json_str)
                            false_positives.append(log_entry)
                    except json.JSONDecodeError:
                        continue
                        
        except Exception as e:
            print(f"{Colors.RED}Error reading log file {log_file}: {e}{Colors.RESET}")
    
    if not false_positives:
        print(f"{Colors.YELLOW}No false positives found{Colors.RESET}")
        return
    
    try:
        with open(output_file, 'w') as f:
            json.dump(false_positives, f, indent=2)
        
        print(f"{Colors.GREEN}Exported {len(false_positives)} false positives to {output_file}{Colors.RESET}")
        
    except Exception as e:
        print(f"{Colors.RED}Error exporting data: {e}{Colors.RESET}")

def export_false_positives_csv():
    """Export false positives to CSV format"""
    import csv
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"false_positives_export_{timestamp}.csv"
    
    # Get all false positives
    log_dir = "logs"
    if not os.path.exists(log_dir):
        print(f"{Colors.YELLOW}No remediation logs found{Colors.RESET}")
        return
    
    log_files = [f for f in os.listdir(log_dir) if f.startswith("remediation_") and f.endswith(".log")]
    
    if not log_files:
        print(f"{Colors.YELLOW}No remediation logs found{Colors.RESET}")
        return
    
    false_positives = []
    
    # Parse all log files for false positive actions
    for log_file in log_files:
        log_path = os.path.join(log_dir, log_file)
        try:
            with open(log_path, 'r') as f:
                lines = f.readlines()
                
            for line in lines:
                if "REMEDIATION ACTION:" in line and "mark_false_positive" in line:
                    try:
                        json_start = line.find('{')
                        if json_start != -1:
                            json_str = line[json_start:]
                            log_entry = json.loads(json_str)
                            false_positives.append(log_entry)
                    except json.JSONDecodeError:
                        continue
                        
        except Exception as e:
            print(f"{Colors.RED}Error reading log file {log_file}: {e}{Colors.RESET}")
    
    if not false_positives:
        print(f"{Colors.YELLOW}No false positives found{Colors.RESET}")
        return
    
    try:
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            
            # Write header
            writer.writerow([
                'Timestamp', 'Threat ID', 'Action', 'Reason', 'Subject', 
                'Attack Type', 'Confidence', 'Sender Email', 'Sender Name', 
                'Received Time', 'Success', 'Action ID'
            ])
            
            # Write data
            for fp in false_positives:
                details = fp.get("threat_details", {})
                writer.writerow([
                    fp.get("timestamp", ""),
                    fp.get("threat_id", ""),
                    fp.get("action", ""),
                    fp.get("reason", ""),
                    details.get("subject", ""),
                    details.get("attack_type", ""),
                    details.get("confidence", ""),
                    details.get("sender_email", ""),
                    details.get("sender_name", ""),
                    details.get("received_time", ""),
                    fp.get("success", False),
                    fp.get("action_id", "")
                ])
        
        print(f"{Colors.GREEN}Exported {len(false_positives)} false positives to {output_file}{Colors.RESET}")
        
    except Exception as e:
        print(f"{Colors.RED}Error exporting data: {e}{Colors.RESET}")

def export_false_positives_summary():
    """Export false positives summary report"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"false_positives_summary_{timestamp}.txt"
    
    # Get all false positives
    log_dir = "logs"
    if not os.path.exists(log_dir):
        print(f"{Colors.YELLOW}No remediation logs found{Colors.RESET}")
        return
    
    log_files = [f for f in os.listdir(log_dir) if f.startswith("remediation_") and f.endswith(".log")]
    
    if not log_files:
        print(f"{Colors.YELLOW}No remediation logs found{Colors.RESET}")
        return
    
    false_positives = []
    
    # Parse all log files for false positive actions
    for log_file in log_files:
        log_path = os.path.join(log_dir, log_file)
        try:
            with open(log_path, 'r') as f:
                lines = f.readlines()
                
            for line in lines:
                if "REMEDIATION ACTION:" in line and "mark_false_positive" in line:
                    try:
                        json_start = line.find('{')
                        if json_start != -1:
                            json_str = line[json_start:]
                            log_entry = json.loads(json_str)
                            false_positives.append(log_entry)
                    except json.JSONDecodeError:
                        continue
                        
        except Exception as e:
            print(f"{Colors.RED}Error reading log file {log_file}: {e}{Colors.RESET}")
    
    if not false_positives:
        print(f"{Colors.YELLOW}No false positives found{Colors.RESET}")
        return
    
    try:
        with open(output_file, 'w') as f:
            f.write("FALSE POSITIVE SUMMARY REPORT\n")
            f.write("=" * 50 + "\n\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total False Positives: {len(false_positives)}\n\n")
            
            # Summary statistics
            attack_types = {}
            sender_domains = {}
            confidence_levels = {}
            
            for fp in false_positives:
                details = fp.get("threat_details", {})
                
                attack_type = details.get("attack_type", "Unknown")
                attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
                
                sender_email = details.get("sender_email", "Unknown")
                sender_domain = sender_email.split('@')[-1] if '@' in sender_email else "Unknown"
                sender_domains[sender_domain] = sender_domains.get(sender_domain, 0) + 1
                
                confidence = details.get("confidence", "Unknown")
                confidence_levels[confidence] = confidence_levels.get(confidence, 0) + 1
            
            f.write("ATTACK TYPE DISTRIBUTION:\n")
            f.write("-" * 30 + "\n")
            for attack_type, count in sorted(attack_types.items(), key=lambda x: x[1], reverse=True):
                percentage = (count / len(false_positives)) * 100
                f.write(f"{attack_type}: {count} ({percentage:.1f}%)\n")
            
            f.write("\nSENDER DOMAIN DISTRIBUTION:\n")
            f.write("-" * 30 + "\n")
            for domain, count in sorted(sender_domains.items(), key=lambda x: x[1], reverse=True):
                percentage = (count / len(false_positives)) * 100
                f.write(f"{domain}: {count} ({percentage:.1f}%)\n")
            
            f.write("\nCONFIDENCE LEVEL DISTRIBUTION:\n")
            f.write("-" * 30 + "\n")
            for confidence, count in sorted(confidence_levels.items(), key=lambda x: x[1], reverse=True):
                percentage = (count / len(false_positives)) * 100
                f.write(f"{confidence}: {count} ({percentage:.1f}%)\n")
            
            f.write("\nDETAILED LISTING:\n")
            f.write("-" * 30 + "\n")
            for i, fp in enumerate(false_positives, 1):
                details = fp.get("threat_details", {})
                f.write(f"{i}. {fp.get('timestamp', 'Unknown')} - {fp.get('threat_id', 'Unknown')}\n")
                f.write(f"   Subject: {details.get('subject', 'No subject')}\n")
                f.write(f"   Attack Type: {details.get('attack_type', 'Unknown')}\n")
                f.write(f"   Sender: {details.get('sender_email', 'Unknown')}\n")
                f.write(f"   Reason: {fp.get('reason', 'No reason')}\n\n")
        
        print(f"{Colors.GREEN}Exported false positive summary to {output_file}{Colors.RESET}")
        
    except Exception as e:
        print(f"{Colors.RED}Error exporting data: {e}{Colors.RESET}")

def generate_false_positive_report(output_file=None):
    """Generate a comprehensive false positive report"""
    print(f"\n{Colors.BOLD}=== False Positive Report Generation ==={Colors.RESET}\n")
    
    if not output_file:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"false_positive_report_{timestamp}.json"
    
    # Get all false positive actions
    log_dir = "logs"
    if not os.path.exists(log_dir):
        print(f"{Colors.YELLOW}No remediation logs found{Colors.RESET}")
        return
    
    log_files = [f for f in os.listdir(log_dir) if f.startswith("remediation_") and f.endswith(".log")]
    
    if not log_files:
        print(f"{Colors.YELLOW}No remediation logs found{Colors.RESET}")
        return
    
    false_positives = []
    
    # Parse all log files for false positive actions
    for log_file in log_files:
        log_path = os.path.join(log_dir, log_file)
        try:
            with open(log_path, 'r') as f:
                lines = f.readlines()
                
            for line in lines:
                if "REMEDIATION ACTION:" in line and "mark_false_positive" in line:
                    try:
                        json_start = line.find('{')
                        if json_start != -1:
                            json_str = line[json_start:]
                            log_entry = json.loads(json_str)
                            false_positives.append(log_entry)
                    except json.JSONDecodeError:
                        continue
                        
        except Exception as e:
            print(f"{Colors.RED}Error reading log file {log_file}: {e}{Colors.RESET}")
    
    if not false_positives:
        print(f"{Colors.YELLOW}No false positives found in logs{Colors.RESET}")
        return
    
    # Generate report
    report = {
        "generated_at": datetime.now().isoformat(),
        "total_false_positives": len(false_positives),
        "time_period": {
            "start": min(fp.get("timestamp", "") for fp in false_positives),
            "end": max(fp.get("timestamp", "") for fp in false_positives)
        },
        "summary": {
            "by_attack_type": {},
            "by_sender_domain": {},
            "by_confidence": {},
            "by_month": {}
        },
        "detailed_entries": false_positives,
        "recommendations": []
    }
    
    # Analyze patterns for summary
    for fp in false_positives:
        details = fp.get("threat_details", {})
        
        # Attack type
        attack_type = details.get("attack_type", "Unknown")
        report["summary"]["by_attack_type"][attack_type] = report["summary"]["by_attack_type"].get(attack_type, 0) + 1
        
        # Sender domain
        sender_email = details.get("sender_email", "Unknown")
        sender_domain = sender_email.split('@')[-1] if '@' in sender_email else "Unknown"
        report["summary"]["by_sender_domain"][sender_domain] = report["summary"]["by_sender_domain"].get(sender_domain, 0) + 1
        
        # Confidence
        confidence = details.get("confidence", "Unknown")
        report["summary"]["by_confidence"][confidence] = report["summary"]["by_confidence"].get(confidence, 0) + 1
        
        # Month
        timestamp = fp.get("timestamp", "")
        if timestamp:
            try:
                month = timestamp[:7]  # YYYY-MM
                report["summary"]["by_month"][month] = report["summary"]["by_month"].get(month, 0) + 1
            except:
                pass
    
    # Generate recommendations
    if report["summary"]["by_attack_type"]:
        most_common_attack = max(report["summary"]["by_attack_type"].items(), key=lambda x: x[1])
        if most_common_attack[1] > len(false_positives) * 0.3:
            report["recommendations"].append(f"Consider adjusting detection rules for '{most_common_attack[0]}' attacks")
    
    if report["summary"]["by_sender_domain"]:
        most_common_domain = max(report["summary"]["by_sender_domain"].items(), key=lambda x: x[1])
        if most_common_domain[1] > len(false_positives) * 0.2:
            report["recommendations"].append(f"Review whitelist for domain '{most_common_domain[0]}'")
    
    # Save report
    try:
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"{Colors.GREEN}False positive report generated successfully{Colors.RESET}")
        print(f"Report saved to: {output_file}")
        print(f"Total false positives analyzed: {len(false_positives)}")
        print(f"Time period: {report['time_period']['start']} to {report['time_period']['end']}")
        
        if report["recommendations"]:
            print(f"\n{Colors.BOLD}Key Recommendations:{Colors.RESET}")
            for rec in report["recommendations"]:
                print(f"• {Colors.YELLOW}{rec}{Colors.RESET}")
                
    except Exception as e:
        print(f"{Colors.RED}Error saving report: {e}{Colors.RESET}")

if __name__ == "__main__":
    main()
