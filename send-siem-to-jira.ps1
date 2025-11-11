# ========================================
# SEND SIEM INCIDENT TO JIRA
# ========================================
# This script sends SIEM-detected incidents to JIRA
# Make sure you have JIRA credentials set in environment variables

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "SIEM INCIDENT → JIRA TICKET GENERATOR" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Check if Python is available
try {
    python --version | Out-Null
    Write-Host "✅ Python is available" -ForegroundColor Green
} catch {
    Write-Host "❌ Python is not installed or not in PATH" -ForegroundColor Red
    exit 1
}

# Check for JIRA credentials
Write-Host "`nChecking JIRA credentials..." -ForegroundColor Yellow
$jiraUrl = $env:JIRA_URL
$jiraUsername = $env:JIRA_USERNAME
$jiraApiToken = $env:JIRA_API_TOKEN
$jiraProjectKey = $env:JIRA_PROJECT_KEY

if (-not $jiraUrl -or -not $jiraUsername -or -not $jiraApiToken) {
    Write-Host "❌ Missing JIRA credentials!" -ForegroundColor Red
    Write-Host "`nPlease set these environment variables:" -ForegroundColor Yellow
    Write-Host '  $env:JIRA_URL="https://your-instance.atlassian.net"' -ForegroundColor Gray
    Write-Host '  $env:JIRA_USERNAME="your-email@example.com"' -ForegroundColor Gray
    Write-Host '  $env:JIRA_API_TOKEN="your-api-token"' -ForegroundColor Gray
    Write-Host '  $env:JIRA_PROJECT_KEY="KAN"  # Optional, defaults to SEC' -ForegroundColor Gray
    Write-Host "`nNote: Your GitHub repository should have these as secrets" -ForegroundColor Cyan
    Write-Host "You can test locally by setting them temporarily`n" -ForegroundColor Cyan
    exit 1
}

if (-not $jiraProjectKey) {
    $jiraProjectKey = "SEC"
    Write-Host "⚠️  Using default project key: SEC" -ForegroundColor Yellow
}

Write-Host "✅ JIRA credentials found!" -ForegroundColor Green
Write-Host "   URL: $jiraUrl" -ForegroundColor Gray
Write-Host "   User: $jiraUsername" -ForegroundColor Gray
Write-Host "   Project: $jiraProjectKey" -ForegroundColor Gray

# Show the SIEM incident report
Write-Host "`n📊 SIEM Incident Report:" -ForegroundColor Cyan
if (Test-Path "scripts\python\siem_incident_report.json") {
    $incidents = Get-Content "scripts\python\siem_incident_report.json" | ConvertFrom-Json
    Write-Host "   Total incidents: $($incidents.summary.total_incidents)" -ForegroundColor White
    Write-Host "   Critical: $($incidents.summary.critical_severity)" -ForegroundColor Red
    Write-Host "   High: $($incidents.summary.high_severity)" -ForegroundColor Yellow
    Write-Host "   SIEM System: $($incidents.summary.siem_system)" -ForegroundColor White
    Write-Host "   Alerts Triggered: $($incidents.summary.alerts_triggered)" -ForegroundColor White
} else {
    Write-Host "   ❌ No incident report found!" -ForegroundColor Red
    exit 1
}

Write-Host "`n🎫 Creating JIRA Tickets..." -ForegroundColor Cyan
Write-Host "   This will create tickets for all incidents in the report" -ForegroundColor Gray

# Ask for confirmation
$confirm = Read-Host "`nDo you want to create JIRA tickets? (Y/N)"
if ($confirm -ne "Y" -and $confirm -ne "y") {
    Write-Host "❌ Cancelled by user" -ForegroundColor Yellow
    exit 0
}

# Change to Python scripts directory
Push-Location scripts\python

# Install dependencies if needed
Write-Host "`n📦 Checking Python dependencies..." -ForegroundColor Yellow
python -c "import requests" 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "   Installing requests library..." -ForegroundColor Yellow
    pip install requests | Out-Null
}

# Create a Python script to send the incidents
$pythonScript = @"
import sys
import os
import json
from jira_ticket_generator import JiraIncidentTicketGenerator

# Load the SIEM incident report
with open('siem_incident_report.json', 'r') as f:
    report = json.load(f)

# Get JIRA credentials from environment
jira_url = os.getenv('JIRA_URL')
jira_username = os.getenv('JIRA_USERNAME')
jira_api_token = os.getenv('JIRA_API_TOKEN')
jira_project_key = os.getenv('JIRA_PROJECT_KEY', 'SEC')

# Initialize JIRA generator
jira = JiraIncidentTicketGenerator(jira_url, jira_username, jira_api_token, jira_project_key)

# Create tickets for each incident
print('\n🎫 Creating JIRA Tickets:\n')
print('-' * 60)

created_tickets = []
for incident in report['incidents']:
    ticket_key = jira.create_incident_ticket(incident)
    if ticket_key:
        created_tickets.append(ticket_key)
        print(f'   ✅ {ticket_key} - {incident[\"type\"]} ({incident[\"severity\"]})')
    else:
        print(f'   ❌ Failed - {incident[\"type\"]}')

print('-' * 60)
print(f'\n✅ Created {len(created_tickets)} JIRA tickets:')
for key in created_tickets:
    print(f'   🎫 {jira_url}/browse/{key}')

print(f'\n📊 Summary:')
print(f'   Total incidents: {report[\"summary\"][\"total_incidents\"]}')
print(f'   Tickets created: {len(created_tickets)}')
print(f'   SIEM System: {report[\"summary\"][\"siem_system\"]}')
"@

# Write the Python script to a temporary file
$pythonScript | Out-File -FilePath "send_to_jira.py" -Encoding UTF8

# Run the Python script
Write-Host ""
python send_to_jira.py

# Clean up
Remove-Item "send_to_jira.py" -ErrorAction SilentlyContinue

Pop-Location

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "✅ JIRA Ticket Creation Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "`nCheck your JIRA project to see the tickets!" -ForegroundColor Yellow
Write-Host "Project: $jiraProjectKey" -ForegroundColor White
Write-Host "URL: $jiraUrl/projects/$jiraProjectKey" -ForegroundColor White
