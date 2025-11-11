"""
JIRA Incident Ticket Generator
Automatically creates JIRA tickets for security incidents with full context.
"""

import requests
import json
import sys
from datetime import datetime

class JiraIncidentTicketGenerator:
    def __init__(self, jira_url, username, api_token, project_key):
        self.jira_url = jira_url.rstrip('/')
        self.auth = (username, api_token)
        self.project_key = project_key
        self.headers = {
            'Content-Type': 'application/json'
        }
    
    def create_incident_ticket(self, incident):
        """
        Create a JIRA ticket for a security incident.
        """
        severity_priority_map = {
            'HIGH': 'Highest',
            'MEDIUM': 'High',
            'LOW': 'Medium'
        }
        
        priority = severity_priority_map.get(incident.get('severity', 'MEDIUM'), 'High')
        
        # Build ticket description
        description = self._build_ticket_description(incident)
        
        # Create issue payload
        issue_data = {
            'fields': {
                'project': {'key': self.project_key},
                'summary': f"[SECURITY] {incident['type']} - {incident.get('username', 'Multiple Users')}",
                'description': description,
                'issuetype': {'name': 'Task'},  # Changed from 'Bug' to 'Task' for Kanban
                'priority': {'name': priority},
                'labels': ['security', 'automated', incident['type'].lower()]
            }
        }
        
        # Note: Custom fields removed for better compatibility across JIRA instances
        
        try:
            response = requests.post(
                f"{self.jira_url}/rest/api/2/issue",
                json=issue_data,
                auth=self.auth,
                headers=self.headers,
                timeout=30
            )
            
            if response.status_code == 201:
                issue_key = response.json()['key']
                print(f"✓ Created JIRA ticket: {issue_key} for {incident['type']}")
                return issue_key
            else:
                print(f"✗ Failed to create ticket: {response.status_code} - {response.text}")
                return None
                
        except Exception as e:
            print(f"✗ Error creating JIRA ticket: {str(e)}")
            return None
    
    def _build_ticket_description(self, incident):
        """
        Build detailed ticket description with all incident context.
        """
        description = f"""
h2. Security Incident Detected

*Incident Type:* {incident['type']}
*Severity:* {incident['severity']}
*Detection Time:* {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

h3. Incident Details
"""
        
        # Add all incident fields
        for key, value in incident.items():
            if key not in ['type', 'severity', 'recommendation']:
                description += f"*{key.replace('_', ' ').title()}:* {value}\n"
        
        if 'recommendation' in incident:
            description += f"""
h3. Recommended Actions
{incident['recommendation']}

h3. Investigation Steps
# Review user activity logs
# Check for similar patterns from same user/IP
# Verify if account is compromised
# Contact user if necessary
# Implement blocking/rate limiting if needed

h3. Root Cause
To be determined during investigation

h3. Remediation Status
[ ] Investigation started
[ ] Root cause identified
[ ] Mitigation applied
[ ] User notified (if applicable)
[ ] Incident resolved
"""
        
        return description
    
    def process_incident_report(self, report_file):
        """
        Process security incident report and create JIRA tickets.
        """
        with open(report_file, 'r') as f:
            report = json.load(f)
        
        incidents = report['incidents']
        print(f"\nProcessing {len(incidents)} incidents from report...")
        print("=" * 80)
        
        created_tickets = []
        failed_tickets = []
        
        # Only create tickets for HIGH and MEDIUM severity
        for incident in incidents:
            if incident.get('severity') in ['HIGH', 'MEDIUM']:
                ticket_key = self.create_incident_ticket(incident)
                if ticket_key:
                    created_tickets.append(ticket_key)
                else:
                    failed_tickets.append(incident['type'])
        
        print("\n" + "=" * 80)
        print(f"JIRA Ticket Summary:")
        print(f"  Created: {len(created_tickets)}")
        print(f"  Failed: {len(failed_tickets)}")
        
        if created_tickets:
            print(f"\nCreated Tickets:")
            for ticket in created_tickets:
                print(f"  - {self.jira_url}/browse/{ticket}")
        
        return created_tickets

def main():
    # Configuration (should be loaded from environment variables or config file)
    JIRA_URL = "https://your-domain.atlassian.net"
    JIRA_USERNAME = "your-email@example.com"
    JIRA_API_TOKEN = "your-api-token"
    PROJECT_KEY = "SEC"
    
    if len(sys.argv) < 2:
        print("Usage: python jira_ticket_generator.py <incident_report.json>")
        sys.exit(1)
    
    report_file = sys.argv[1]
    
    generator = JiraIncidentTicketGenerator(JIRA_URL, JIRA_USERNAME, JIRA_API_TOKEN, PROJECT_KEY)
    created_tickets = generator.process_incident_report(report_file)
    
    sys.exit(0 if created_tickets else 1)

if __name__ == "__main__":
    main()
