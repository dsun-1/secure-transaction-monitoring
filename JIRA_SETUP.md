# 🎯 JIRA Integration Setup Guide

## ✅ What You Have
- Free JIRA account at https://secure-transaction.atlassian.net
- JIRA integration code ready (171 lines Python)
- GitHub Actions workflow configured

## 📋 Setup Steps

### Step 1: Generate JIRA API Token

1. Go to: https://id.atlassian.com/manage-profile/security/api-tokens
2. Click **"Create API token"**
3. Name: `GitHub Actions CI/CD`
4. Click **"Create"**
5. **Copy the token** (you won't see it again!)

### Step 2: Create JIRA Project

1. Go to: https://secure-transaction.atlassian.net
2. Click **"Projects"** → **"Create project"**
3. Choose any template (Kanban recommended)
4. **Project name:** `Security Incidents`
5. **Project key:** `SEC` (must be exactly this!)
6. Click **"Create"**

### Step 3: Add GitHub Secrets

1. Go to: https://github.com/dsun-1/secure-transaction-monitoring/settings/secrets/actions
2. Click **"New repository secret"** for each:

| Name | Value | Where to Get It |
|------|-------|-----------------|
| `JIRA_URL` | `https://secure-transaction.atlassian.net` | Your JIRA URL |
| `JIRA_USERNAME` | `your-email@example.com` | Email you used for JIRA |
| `JIRA_API_TOKEN` | `ATATT3xFfGF0...` | From Step 1 |

**Note:** `JIRA_PROJECT_KEY` is already set to `SEC` in the workflow

### Step 4: Test Locally (Optional)

Test before running in GitHub Actions:

```powershell
cd scripts\python

# Set environment variables (replace with your values)
$env:JIRA_URL="https://secure-transaction.atlassian.net"
$env:JIRA_USERNAME="darshsundar007@gmail.com"
$env:JIRA_API_TOKEN="your-api-token-here"
$env:JIRA_PROJECT_KEY="KAN"  # Your project key

# Test with single ticket
python test_jira_integration.py

# Or test with full report
python jira_ticket_generator.py sample_incident_report.json
```

**Expected output:**
```
✅ SUCCESS! Ticket created: KAN-1
🔗 View it at: https://secure-transaction.atlassian.net/browse/KAN-1
🎉 JIRA integration is working correctly!
```

### Step 5: Trigger GitHub Actions

Once secrets are added:

1. Go to: https://github.com/dsun-1/secure-transaction-monitoring/actions
2. Click **"Security Test Suite & Incident Response"**
3. Click **"Run workflow"** → **"Run workflow"**

Or just push a commit:
```bash
git commit --allow-empty -m "Test JIRA integration"
git push origin main
```

---

## 🎯 What Happens When It Works

1. GitHub Actions runs your security tests
2. If security events are detected, Python analyzer runs
3. High/Medium severity incidents trigger JIRA ticket creation
4. Tickets appear in your JIRA project with:
   - **Priority:** Highest (HIGH), High (MEDIUM), Medium (LOW)
   - **Description:** Detailed incident info
   - **Investigation checklist:** Steps to investigate
   - **Timestamps:** When the incident occurred

---

## 📝 Example Ticket That Gets Created

**Title:** `[HIGH SEVERITY] BRUTE_FORCE_DETECTED - admin`

**Description:**
```
Security Incident Report
========================

Severity: HIGH
Type: BRUTE_FORCE_DETECTED
Detected: 2025-11-10 19:30:45

Incident Details
----------------
Username: admin
IP Address: 192.168.1.100
Failed Attempts: 15
Time Window: 5 minutes

Investigation Steps
-------------------
1. Review authentication logs
2. Check if account was compromised
3. Verify IP address legitimacy
4. Check for successful logins after attempts
5. Consider blocking IP if malicious
```

---

## ⚠️ Common Issues

### "Project 'SEC' not found"
- Create project in JIRA with exact key **SEC**
- Or change `JIRA_PROJECT_KEY` in workflow to match your project

### "Authentication failed"
- Regenerate API token
- Make sure username is your email
- Check URL has https:// and no trailing slash

### "Permission denied"
- API token user must have permission to create issues
- Go to JIRA → Project Settings → Permissions
- Make sure your user has "Create Issues" permission

---

## 🎉 Success Checklist

- [ ] JIRA account created
- [ ] API token generated
- [ ] Project "SEC" created in JIRA
- [ ] GitHub secrets added (JIRA_URL, JIRA_USERNAME, JIRA_API_TOKEN)
- [ ] Local test passed (optional)
- [ ] GitHub Actions workflow triggered
- [ ] Ticket appeared in JIRA

---

## 📞 Need Help?

If stuck, check:
1. GitHub Actions logs: https://github.com/dsun-1/secure-transaction-monitoring/actions
2. JIRA audit log: https://secure-transaction.atlassian.net/secure/admin/ViewLogging.jspa
3. Your JIRA project: https://secure-transaction.atlassian.net/projects/SEC

---

**Your workflow is already configured - just add the 3 secrets and you're done!** 🚀
