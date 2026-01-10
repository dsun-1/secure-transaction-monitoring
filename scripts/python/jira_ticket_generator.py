
import argparse
import json
import logging
import os
import sys
from datetime import datetime

import requests


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
            logger.error("Failed to create ticket: %s - %s", response.status_code, response.text)
            if response.status_code in (401, 403):
                logger.error(
                    "Authentication to JIRA failed (status %s). Check JIRA credentials or token expiry.",
                    response.status_code,
                )
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

    def process_incident_report(self, report_file, incident_type):
        with open(report_file, 'r') as f:
            report = json.load(f)

        incidents = build_incident_list(report)
        filtered = [i for i in incidents if matches_incident_type(i, incident_type)]
        logger.info("Processing %d incidents from report %s", len(filtered), report_file)
        logger.debug("Full report keys: %s", ','.join(report.keys()))

        created_tickets = []
        failed_tickets = []

        for incident in filtered:
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


def build_incident_list(report):
    incidents = list(report.get('incidents', []))
    high_events = report.get('high_severity_events', [])

    for event in high_events:
        incidents.append({
            'type': event.get('event_type', 'HIGH_SEVERITY_EVENT'),
            'severity': event.get('severity', 'HIGH'),
            'username': event.get('username'),
            'ip_address': event.get('ip_address'),
            'details': event.get('details'),
            'suspected_threat': event.get('suspected_threat'),
            'timestamp': event.get('timestamp'),
        })

    deduped = []
    seen = set()
    for incident in incidents:
        key = (
            incident.get('type'),
            incident.get('username'),
            incident.get('timestamp'),
            incident.get('details'),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(incident)

    return deduped


def matches_incident_type(incident, incident_type):
    if not incident_type or incident_type == "all_patterns":
        return True

    incident_value = (incident.get('type') or '').upper()
    if incident_type == "brute_force":
        return "BRUTE_FORCE" in incident_value
    if incident_type == "sql_injection":
        return "SQL_INJECTION" in incident_value
    if incident_type == "privilege_escalation":
        return "PRIVILEGE_ESCALATION" in incident_value
    return True


def parse_args():
    parser = argparse.ArgumentParser(description="Create JIRA tickets from a SIEM incident report.")
    parser.add_argument(
        "report_file",
        nargs="?",
        default=os.getenv("REPORT_FILE", "siem_incident_report.json"),
        help="Path to the incident report JSON.",
    )
    parser.add_argument(
        "--incident-type",
        dest="incident_type",
        default=os.getenv("INCIDENT_TYPE", "all_patterns"),
        help="Filter incidents (brute_force, sql_injection, privilege_escalation, all_patterns).",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    JIRA_URL = os.getenv('JIRA_URL')
    JIRA_USERNAME = os.getenv('JIRA_USERNAME')
    JIRA_API_TOKEN = os.getenv('JIRA_API_TOKEN')
    PROJECT_KEY = os.getenv('JIRA_PROJECT_KEY', 'KAN')

    dry_run = False
    if not all([JIRA_URL, JIRA_USERNAME, JIRA_API_TOKEN]):
        logger.warning('JIRA credentials not provided; running in dry-run mode (no tickets will be created).')
        dry_run = True

    report_file = args.report_file
    incident_type = (args.incident_type or "all_patterns").strip().lower()

    logger.info('Project: %s', PROJECT_KEY)

    if dry_run:
        with open(report_file, 'r') as f:
            report = json.load(f)
        incidents = build_incident_list(report)
        filtered = [i for i in incidents if matches_incident_type(i, incident_type)]
        to_create = [i for i in filtered if i.get('severity') in ['HIGH', 'MEDIUM']]
        logger.info('Dry-run: would create %d JIRA tickets (HIGH/MEDIUM)', len(to_create))
        for incident in to_create:
            logger.info(
                '[DRY-RUN] %s | %s | severity=%s',
                incident.get('type'),
                incident.get('username', 'N/A'),
                incident.get('severity'),
            )
        sys.exit(0)

    logger.info('Connecting to JIRA: %s', JIRA_URL)
    generator = JiraIncidentTicketGenerator(JIRA_URL, JIRA_USERNAME, JIRA_API_TOKEN, PROJECT_KEY)
    created_tickets = generator.process_incident_report(report_file, incident_type)
    if not created_tickets:
        logger.warning(
            'No tickets were created. Check credentials and API access. '
            'If running in CI, ensure repository secrets are mapped to environment variables.'
        )
    sys.exit(0 if created_tickets else 1)


if __name__ == "__main__":
    main()
