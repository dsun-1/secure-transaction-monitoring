
import sys
import os

                                                              
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from jira_ticket_generator import JiraIncidentTicketGenerator

                    
test_incident = {
    "type": "BRUTE_FORCE_DETECTED",
    "severity": "HIGH",
    "username": "test_user",
    "ip_address": "192.168.1.100",
    "attempt_count": 15,
    "first_attempt": "2025-11-10 19:00:00",
    "last_attempt": "2025-11-10 19:05:00",
    "details": "Multiple failed login attempts detected from same IP address"
}

def main():
    print("🔍 Testing JIRA Integration...")
    print("-" * 60)
    
                                                
    jira_url = os.getenv("JIRA_URL")
    jira_username = os.getenv("JIRA_USERNAME")
    jira_api_token = os.getenv("JIRA_API_TOKEN")
    jira_project_key = os.getenv("JIRA_PROJECT_KEY", "SEC")
    
                                       
    if not all([jira_url, jira_username, jira_api_token]):
        print("❌ Error: Missing JIRA credentials!")
        print()
        print("Please set these environment variables:")
        print("  JIRA_URL          - Your JIRA instance URL")
        print("  JIRA_USERNAME     - Your JIRA email")
        print("  JIRA_API_TOKEN    - Your JIRA API token")
        print("  JIRA_PROJECT_KEY  - Project key (default: SEC)")
        print()
        print("Example (PowerShell):")
        print('  $env:JIRA_URL="https://secure-transaction.atlassian.net"')
        print('  $env:JIRA_USERNAME="your-email@example.com"')
        print('  $env:JIRA_API_TOKEN="your-api-token-here"')
        print('  python test_jira_integration.py')
        return 1
    
    print(f"✅ JIRA URL: {jira_url}")
    print(f"✅ Username: {jira_username}")
    print(f"✅ Project Key: {jira_project_key}")
    print(f"✅ API Token: {'*' * 20}...{jira_api_token[-4:]}")
    print("-" * 60)
    
    try:
                                
        print("\n📡 Connecting to JIRA...")
        jira = JiraIncidentTicketGenerator(
            jira_url=jira_url,
            username=jira_username,
            api_token=jira_api_token,
            project_key=jira_project_key
        )
        
                            
        print("🎫 Creating test security incident ticket...")
        ticket_key = jira.create_incident_ticket(test_incident)
        
        if ticket_key:
            print(f"\n✅ SUCCESS! Ticket created: {ticket_key}")
            print(f"🔗 View it at: {jira_url}/browse/{ticket_key}")
            print()
            print("🎉 JIRA integration is working correctly!")
            print("You can now use it in GitHub Actions.")
            return 0
        else:
            print("\n❌ Failed to create ticket")
            print("Check the error messages above.")
            return 1
            
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")
        print()
        print("Common issues:")
        print("  1. Wrong JIRA URL (should be https://your-instance.atlassian.net)")
        print("  2. Invalid API token (regenerate at id.atlassian.com)")
        print("  3. Project 'SEC' doesn't exist (create it in JIRA)")
        print("  4. API token doesn't have permission to create issues")
        return 1

if __name__ == "__main__":
    sys.exit(main())
