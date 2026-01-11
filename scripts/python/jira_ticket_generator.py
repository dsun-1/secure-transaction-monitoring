
import logging
import requests
import json
import sys
import os
from datetime import datetime

                  
logger = logging.getLogger('jira_generator')
if not logger.handlers:
    h = logging.StreamHandler()
    fmt = logging.Formatter('%(asctime)s [%(levelname)s] %(name)s: %(message)s')
    h.setFormatter(fmt)
    logger.addHandler(h)
logger.setLevel(logging.INFO)

def _load_env_file(path):
    if not path or not os.path.exists(path):
        return False
    try:
        with open(path, 'r') as env_file:
            for raw_line in env_file:
                line = raw_line.strip()
                if not line or line.startswith('#'):
                    continue
                if '=' not in line:
                    continue
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip()
                if not key:
                    continue
                if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
                    value = value[1:-1]
                else:
                    if '#' in value:
                        value = value.split('#', 1)[0].rstrip()
                if key not in os.environ and value != '':
                    os.environ[key] = value
        return True
    except Exception as exc:
        logger.warning('Failed to load env file %s: %s', path, exc)
        return False

def _load_env_files():
    env_paths = []
    explicit = os.getenv('JIRA_ENV_FILE')
    if explicit:
        env_paths.append(explicit)
    cwd = os.getcwd()
    env_paths.append(os.path.join(cwd, 'jira.env'))
    env_paths.append(os.path.join(cwd, '.env'))
    script_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
    env_paths.append(os.path.join(script_root, 'jira.env'))
    env_paths.append(os.path.join(script_root, '.env'))
    for path in env_paths:
        if _load_env_file(path):
            logger.info('Loaded environment variables from %s', path)
            return

class JiraIncidentTicketGenerator:
    def __init__(self, jira_url, username, api_token, project_key):
        self.jira_url = jira_url.rstrip('/')
        self.auth = (username, api_token)
        self.project_key = project_key
        self.headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        self.use_service_desk = os.getenv('JIRA_SERVICE_DESK', '').lower() in ('1', 'true', 'yes')
        self.request_type_name = os.getenv('JIRA_REQUEST_TYPE')
        self.issue_type = (os.getenv('JIRA_ISSUE_TYPE') or 'Task').strip() or 'Task'
        self._service_desk_id = None
        self._request_type_id = None
    
    def create_incident_ticket(self, incident):
        severity_priority_map = {
            'HIGH': 'Highest',
            'MEDIUM': 'High',
            'LOW': 'Medium'
        }
        
        priority = severity_priority_map.get(incident.get('severity', 'MEDIUM'), 'High')
        
        if self.use_service_desk:
            return self.create_service_desk_request(incident)

        description = self._build_ticket_description(incident)
        
                              
        issue_data = {
            'fields': {
                'project': {'key': self.project_key},
                'summary': f"[SECURITY] {incident['type']} - {incident.get('username', 'Multiple Users')}",
                'description': description,
                'issuetype': {'name': self.issue_type},                                           
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

    def create_service_desk_request(self, incident):
        service_desk_id = self._resolve_service_desk_id()
        if not service_desk_id:
            logger.error("Unable to resolve service desk for project key: %s", self.project_key)
            return None

        request_type_id = self._resolve_request_type_id(service_desk_id)
        if not request_type_id:
            logger.error("Unable to resolve request type for service desk %s", service_desk_id)
            return None

        summary = f"[SECURITY] {incident['type']} - {incident.get('username', 'Multiple Users')}"
        description = self._build_ticket_description(incident)

        request_data = {
            'serviceDeskId': str(service_desk_id),
            'requestTypeId': str(request_type_id),
            'requestFieldValues': {
                'summary': summary,
                'description': description
            }
        }

        try:
            logger.debug("Creating JSM request for incident: %s", incident.get('type'))
            response = requests.post(
                f"{self.jira_url}/rest/servicedeskapi/request",
                json=request_data,
                auth=self.auth,
                headers=self.headers,
                timeout=30
            )

            if response.status_code == 201:
                issue_key = response.json().get('issueKey')
                logger.info("Created JSM request: %s for %s", issue_key, incident.get('type'))
                return issue_key
            else:
                logger.error("Failed to create JSM request: %s - %s", response.status_code, response.text)
                if response.status_code in (401, 403):
                    logger.error("Authentication/authorization failed for JSM (status %s).", response.status_code)
                return None
        except Exception as e:
            logger.exception("Error creating JSM request: %s", e)
            return None

    def _resolve_service_desk_id(self):
        if self._service_desk_id:
            return self._service_desk_id

        try:
            response = requests.get(
                f"{self.jira_url}/rest/servicedeskapi/servicedesk",
                auth=self.auth,
                headers=self.headers,
                timeout=30
            )
            if response.status_code != 200:
                logger.error("Failed to list service desks: %s - %s", response.status_code, response.text)
                return None

            desks = response.json().get('values', [])
            for desk in desks:
                project_key = desk.get('projectKey')
                if project_key and project_key.upper() == self.project_key.upper():
                    self._service_desk_id = desk.get('id')
                    return self._service_desk_id
        except Exception as e:
            logger.exception("Error resolving service desk: %s", e)
        return None

    def _resolve_request_type_id(self, service_desk_id):
        if self._request_type_id:
            return self._request_type_id

        try:
            response = requests.get(
                f"{self.jira_url}/rest/servicedeskapi/servicedesk/{service_desk_id}/requesttype",
                auth=self.auth,
                headers=self.headers,
                timeout=30
            )
            if response.status_code != 200:
                logger.error("Failed to list request types: %s - %s", response.status_code, response.text)
                return None

            request_types = response.json().get('values', [])
            if self.request_type_name:
                for req_type in request_types:
                    if req_type.get('name', '').lower() == self.request_type_name.lower():
                        self._request_type_id = req_type.get('id')
                        return self._request_type_id

            if request_types:
                self._request_type_id = request_types[0].get('id')
                return self._request_type_id
        except Exception as e:
            logger.exception("Error resolving request type: %s", e)
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
    _load_env_files()
    
                                                   
    JIRA_URL = (os.getenv('JIRA_URL') or '').strip() or None
    JIRA_USERNAME = (os.getenv('JIRA_USERNAME') or '').strip() or None
    JIRA_API_TOKEN = (os.getenv('JIRA_API_TOKEN') or '').strip() or None
    PROJECT_KEY = (os.getenv('JIRA_PROJECT_KEY') or '').strip() or None
    JIRA_DRY_RUN = os.getenv('JIRA_DRY_RUN', '').lower() in ('1', 'true', 'yes')
                                                        
    dry_run = False
    if JIRA_DRY_RUN:
        logger.warning('JIRA_DRY_RUN enabled - running in dry-run mode (no tickets will be created).')
        dry_run = True
    elif not all([JIRA_URL, JIRA_USERNAME, JIRA_API_TOKEN, PROJECT_KEY]):
        missing = []
        if not JIRA_URL:
            missing.append('JIRA_URL')
        if not JIRA_USERNAME:
            missing.append('JIRA_USERNAME')
        if not JIRA_API_TOKEN:
            missing.append('JIRA_API_TOKEN')
        if not PROJECT_KEY:
            missing.append('JIRA_PROJECT_KEY')
        logger.error('Missing required JIRA settings: %s', ', '.join(missing))
        logger.warning('JIRA credentials not provided - running in dry-run mode (no tickets will be created).')
        dry_run = True
    else:
        if not (JIRA_URL.startswith('http://') or JIRA_URL.startswith('https://')):
            logger.error('JIRA_URL must start with http:// or https:// (got: %s)', JIRA_URL)
            dry_run = True
        try:
            requests.get(JIRA_URL, timeout=5)
        except Exception as e:
            logger.warning('JIRA URL unreachable (%s) - running in dry-run mode.', e)
            dry_run = True
        if not dry_run:
            auth = (JIRA_USERNAME, JIRA_API_TOKEN)
            headers = {'Accept': 'application/json'}
            try:
                auth_check = requests.get(
                    f"{JIRA_URL.rstrip('/')}/rest/api/2/myself",
                    auth=auth,
                    headers=headers,
                    timeout=10
                )
                if auth_check.status_code in (401, 403):
                    logger.error('JIRA authentication failed (status %s). Check JIRA_USERNAME and JIRA_API_TOKEN.', auth_check.status_code)
                    dry_run = True
                elif auth_check.status_code >= 400:
                    logger.error('JIRA auth check failed (status %s): %s', auth_check.status_code, auth_check.text)
                    dry_run = True
            except Exception as e:
                logger.warning('JIRA auth check failed (%s) - running in dry-run mode.', e)
                dry_run = True

        if not dry_run:
            try:
                project_check = requests.get(
                    f"{JIRA_URL.rstrip('/')}/rest/api/2/project/{PROJECT_KEY}",
                    auth=auth,
                    headers=headers,
                    timeout=10
                )
                if project_check.status_code == 404:
                    logger.error('JIRA project key not found: %s', PROJECT_KEY)
                    dry_run = True
                elif project_check.status_code in (401, 403):
                    logger.error('JIRA project access denied (status %s). Check permissions for %s.', project_check.status_code, PROJECT_KEY)
                    dry_run = True
                elif project_check.status_code >= 400:
                    logger.error('JIRA project check failed (status %s): %s', project_check.status_code, project_check.text)
                    dry_run = True
            except Exception as e:
                logger.warning('JIRA project check failed (%s) - running in dry-run mode.', e)
                dry_run = True

                                                                               
    if len(sys.argv) < 2:
        report_file = 'siem_incident_report.json'
        print(f"No report file provided, using default: {report_file}")
    else:
        report_file = sys.argv[1]
    
    logger.info('Project: %s', PROJECT_KEY or 'N/A')

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
