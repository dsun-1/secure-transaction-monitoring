
import logging
import requests
import json
import sys
from datetime import datetime

                  
logger = logging.getLogger('jira_generator')
if not logger.handlers:
    h = logging.StreamHandler()
    fmt = logging.Formatter('%(asctime)s [%(levelname)s] %(name)s: %(message)s')
    h.setFormatter(fmt)
    logger.addHandler(h)
logger.setLevel(logging.INFO)

class JiraIncidentTicketGenerator:
    def __init__(self, jira_url, username, api_token, project_key):
        self.jira_url = jira_url.rstrip('/')
        self.auth = (username, api_token)
        self.project_key = project_key
        self.headers = {
            'Content-Type': 'application/json'
        }
    
    def create_incident_ticket(self, incident):
        severity_priority_map = {
            'HIGH': 'Highest',
            'MEDIUM': 'High',
            'LOW': 'Medium'
        }
        
        priority = severity_priority_map.get(incident.get('severity', 'MEDIUM'), 'High')
        
                                  
        description = self._build_ticket_description(incident)
        
                              
        issue_data = {
            'fields': {
                'project': {'key': self.project_key},
                'summary': f"[SECURITY] {incident['type']} - {incident.get('username', 'Multiple Users')}",
                'description': description,
                'issuetype': {'name': 'Task'},                                           
                'priority': {'name': priority},
                'labels': ['security', 'automated', incident['type'].lower()]
            }
        }
        
                                                                                    
        
        try:
            logger.debug("Creating JIRA ticket for incident: %s", incident.get('type'))
            response = requests.post(
                f"{self.jira_url}/rest/api/2/issue",
                json=issue_data,
                auth=self.auth,
                headers=self.headers,
                timeout=30
            )

            if response.status_code == 201:
                issue_key = response.json().get('key')
                logger.info("Created JIRA ticket: %s for %s", issue_key, incident.get('type'))
                return issue_key
            else:
                logger.error("Failed to create ticket: %s - %s", response.status_code, response.text)
                                                               
                if response.status_code in (401, 403):
                    logger.error("Authentication to JIRA failed (status %s). Check JIRA credentials or token expiry.", response.status_code)
                return None

        except Exception as e:
            logger.exception("Error creating JIRA ticket: %s", e)
            return None
    
    def _build_ticket_description(self, incident):
        description = f"""
h2. Security Incident Detected

*Incident Type:* {incident['type']}
*Severity:* {incident['severity']}
*Detection Time:* {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

h3. Incident Details
"""
        
                                 
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
        with open(report_file, 'r') as f:
            report = json.load(f)
        
        incidents = report.get('incidents', [])
        logger.info("Processing %d incidents from report %s", len(incidents), report_file)
        logger.debug("Full report keys: %s", ','.join(report.keys()))
        
        created_tickets = []
        failed_tickets = []
        
                                                          
        for incident in incidents:
            if incident.get('severity') in ['HIGH', 'MEDIUM']:
                ticket_key = self.create_incident_ticket(incident)
                if ticket_key:
                    created_tickets.append(ticket_key)
                else:
                    failed_tickets.append(incident['type'])
        
        logger.info("JIRA Ticket Summary: Created=%d Failed=%d", len(created_tickets), len(failed_tickets))
        if created_tickets:
            logger.info("Created tickets:")
            for ticket in created_tickets:
                logger.info(" - %s/browse/%s", self.jira_url, ticket)

        return created_tickets

def main():
    import os
    
                                                   
    JIRA_URL = os.getenv('JIRA_URL')
    JIRA_USERNAME = os.getenv('JIRA_USERNAME')
    JIRA_API_TOKEN = os.getenv('JIRA_API_TOKEN')
    PROJECT_KEY = os.getenv('JIRA_PROJECT_KEY', 'KAN')
    JIRA_DRY_RUN = os.getenv('JIRA_DRY_RUN', '').lower() in ('1', 'true', 'yes')
                                                        
    dry_run = False
    if JIRA_DRY_RUN:
        logger.warning('JIRA_DRY_RUN enabled — running in dry-run mode (no tickets will be created).')
        dry_run = True
    elif not all([JIRA_URL, JIRA_USERNAME, JIRA_API_TOKEN]):
        logger.warning('JIRA credentials not provided — running in dry-run mode (no tickets will be created).')
        dry_run = True
    else:
        try:
            requests.get(JIRA_URL, timeout=5)
        except Exception as e:
            logger.warning('JIRA URL unreachable (%s) — running in dry-run mode.', e)
            dry_run = True

                                                                               
    if len(sys.argv) < 2:
        report_file = 'siem_incident_report.json'
        print(f"No report file provided, using default: {report_file}")
    else:
        report_file = sys.argv[1]
    
    logger.info('Project: %s', PROJECT_KEY)

    if dry_run:
                                                     
        with open(report_file, 'r') as f:
            report = json.load(f)
        incidents = report.get('incidents', [])
        to_create = [i for i in incidents if i.get('severity') in ['HIGH', 'MEDIUM']]
        logger.info('Dry-run: would create %d JIRA tickets (HIGH/MEDIUM)', len(to_create))
        for incident in to_create:
            logger.info('[DRY-RUN] %s | %s | severity=%s', incident.get('type'), incident.get('username', 'N/A'), incident.get('severity'))
        sys.exit(0)
    else:
        logger.info('Connecting to JIRA: %s', JIRA_URL)
        generator = JiraIncidentTicketGenerator(JIRA_URL, JIRA_USERNAME, JIRA_API_TOKEN, PROJECT_KEY)
        created_tickets = generator.process_incident_report(report_file)
        if not created_tickets:
            logger.warning('No tickets were created. Check credentials and API access. If running in CI, ensure repository secrets are mapped to environment variables.')
        sys.exit(0 if created_tickets else 1)

if __name__ == "__main__":
    main()
