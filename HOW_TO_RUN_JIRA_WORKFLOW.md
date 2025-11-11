# 🚀 How to Run the JIRA Ticket Creation Workflow

## Step-by-Step Guide

### 1️⃣ Go to Your GitHub Repository
Open your browser and navigate to:
```
https://github.com/dsun-1/secure-transaction-monitoring
```

### 2️⃣ Click on "Actions" Tab
At the top of your repository page, you'll see several tabs:
- `<> Code`
- `Issues`
- `Pull requests`
- **`Actions`** ← Click this one!

### 3️⃣ Find the Workflow
On the left sidebar, you'll see a list of workflows. Look for:
```
📋 Manual JIRA Ticket Generation
```
Click on it.

### 4️⃣ Click "Run workflow"
You'll see a blue button on the right side that says:
```
Run workflow ▼
```
Click it!

### 5️⃣ Configure the Workflow (Optional)
A dropdown will appear with options:
- **Branch**: `main` (leave as is)
- **Type of security incident**: Choose one:
  - `brute_force` - Brute force attack patterns
  - `sql_injection` - SQL injection attempts
  - `privilege_escalation` - Privilege escalation attempts
  - `all_patterns` - Run all detection patterns

### 6️⃣ Click the Green "Run workflow" Button
Click the green button at the bottom of the dropdown.

### 7️⃣ Watch the Workflow Run
- The workflow will appear in the list
- It will show a yellow circle 🟡 while running
- It will show a green checkmark ✅ when complete
- Click on the workflow run to see detailed logs

---

## 📋 What This Workflow Does

1. **Checks out your code** from GitHub
2. **Sets up Java 21** and builds your Spring Boot app
3. **Starts the application** in the background
4. **Runs security tests** (based on your selection)
5. **Analyzes the H2 database** for security incidents
6. **Detects patterns** using Python scripts:
   - Brute force attacks
   - SQL injection attempts
   - Privilege escalation
   - Distributed attacks
7. **Creates JIRA tickets** automatically for detected incidents!

---

## ⚙️ Required: Set Up GitHub Secrets First!

**Before running the workflow**, you need to add your JIRA credentials to GitHub Secrets:

### How to Add Secrets:

1. Go to your repository on GitHub
2. Click **Settings** tab (top right)
3. In the left sidebar, scroll down to **Security** section
4. Click **Secrets and variables** → **Actions**
5. Click **New repository secret** button
6. Add these **4 secrets** one by one:

| Secret Name | Example Value | Description |
|-------------|---------------|-------------|
| `JIRA_URL` | `https://yourcompany.atlassian.net` | Your JIRA instance URL |
| `JIRA_USERNAME` | `your-email@example.com` | Your JIRA email/username |
| `JIRA_API_TOKEN` | `ATATT3xFfGF0...` | Your JIRA API token |
| `JIRA_PROJECT_KEY` | `SEC` or `KAN` | Your JIRA project key |

### How to Get a JIRA API Token:

1. Go to: https://id.atlassian.com/manage-profile/security/api-tokens
2. Click **Create API token**
3. Give it a name like "GitHub Actions"
4. Click **Create**
5. **Copy the token** (you won't see it again!)
6. Paste it into the `JIRA_API_TOKEN` secret in GitHub

---

## 🎯 Alternative: Run Locally

If you don't want to use GitHub Actions, you can run the script locally:

### Option 1: Use the PowerShell Script
```powershell
# Set credentials temporarily
$env:JIRA_URL="https://your-instance.atlassian.net"
$env:JIRA_USERNAME="your-email@example.com"
$env:JIRA_API_TOKEN="your-api-token"
$env:JIRA_PROJECT_KEY="SEC"

# Run the script
.\send-siem-to-jira.ps1
```

### Option 2: Run Python Script Directly
```powershell
cd scripts\python

# Set environment variables
$env:JIRA_URL="https://your-instance.atlassian.net"
$env:JIRA_USERNAME="your-email@example.com"
$env:JIRA_API_TOKEN="your-api-token"
$env:JIRA_PROJECT_KEY="SEC"

# Run the test
python test_jira_integration.py
```

---

## 🎫 What JIRA Tickets Look Like

When the workflow runs successfully, it creates tickets like this:

### Example Ticket 1: Brute Force Attack
```
Priority: Highest
Type: Security Incident
Summary: SIEM Alert: Brute Force Attack Pattern Detected

Description:
Correlation ID: CORR-20241111-001
Threat Score: 85/100
Detected: 2024-11-11 14:23:45

DETAILS:
- Attack Pattern: SIEM_CORRELATION_ALERT
- Source IP: 203.0.113.42
- Attacks Detected: 8 failed login attempts
- Time Window: 5 minutes
- Target Accounts: testuser

RECOMMENDATIONS:
1. Block IP address 203.0.113.42 immediately
2. Force password reset for affected accounts
3. Enable rate limiting on login endpoints
4. Review security logs for related incidents
```

### Example Ticket 2: Distributed Attack
```
Priority: Highest (Critical)
Type: Security Incident
Summary: SIEM Alert: Distributed Attack Campaign

Description:
Correlation ID: CORR-20241111-002
Threat Score: 95/100
Detected: 2024-11-11 14:25:12

DETAILS:
- Attack Pattern: DISTRIBUTED_ATTACK_DETECTED
- Source IPs: 12 unique addresses
- Total Attacks: 47 attempts across 5 accounts
- Coordinated: Yes (distributed attack pattern)

RECOMMENDATIONS:
1. Implement IP-based rate limiting
2. Enable WAF rules for attack patterns
3. Monitor for continued activity
4. Consider implementing CAPTCHA
```

---

## ✅ Success Indicators

You'll know it worked when:

1. ✅ Workflow shows green checkmark in GitHub Actions
2. ✅ Workflow logs show "Created JIRA ticket: SEC-XXX"
3. ✅ You see new tickets in your JIRA project
4. ✅ Tickets have labels: `security-incident`, `siem-detected`
5. ✅ Tickets contain correlation IDs and threat scores

---

## 🐛 Troubleshooting

### Error: "JIRA authentication failed"
- Check that all 4 secrets are set correctly in GitHub
- Verify your JIRA API token is valid
- Make sure your JIRA_USERNAME matches your JIRA account

### Error: "Project key not found"
- Check that `JIRA_PROJECT_KEY` matches an actual project in your JIRA
- Make sure you have permission to create issues in that project

### Error: "No security incidents detected"
- Run some security tests first to generate incidents
- Check that the H2 database has events in `security_event` table
- Try running with `all_patterns` option

### Workflow doesn't appear in Actions
- Make sure the `.github/workflows/manual-jira-tickets.yml` file is committed to `main` branch
- Check that the YAML syntax is valid
- Refresh the GitHub Actions page

---

## 📞 Need Help?

Check these resources:
1. **GitHub Actions Logs**: Click on the workflow run to see detailed logs
2. **JIRA API Docs**: https://developer.atlassian.com/cloud/jira/platform/rest/v2/
3. **Workflow File**: `.github/workflows/manual-jira-tickets.yml`
4. **Python Scripts**: `scripts/python/jira_ticket_generator.py`

---

## 🎥 For Your Demo

When presenting this for your internship:

1. **Show the GitHub Actions tab** - "This is our CI/CD pipeline"
2. **Click Run workflow** - "We can manually trigger security analysis"
3. **Select a pattern** - "Let's analyze brute force attacks"
4. **Show the logs** - "The system builds the app, runs tests, analyzes patterns"
5. **Show the JIRA tickets** - "And automatically creates incident tickets!"

This demonstrates:
- ✅ CI/CD automation
- ✅ Security monitoring
- ✅ Incident management
- ✅ Integration between systems
- ✅ Real-world DevSecOps workflow

**Pro tip**: Run it once before your demo to make sure everything works! 🚀
