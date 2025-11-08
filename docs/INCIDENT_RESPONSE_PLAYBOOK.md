# Security Incident Response Playbook

## Table of Contents
1. [Overview](#overview)
2. [Incident Severity Levels](#incident-severity-levels)
3. [Detection → Triage → Containment Process](#detection--triage--containment-process)
4. [Incident Types & Response Procedures](#incident-types--response-procedures)
5. [Escalation Matrix](#escalation-matrix)
6. [Communication Templates](#communication-templates)

---

## Overview

This playbook defines the incident response procedures for security events detected in the e-commerce transaction monitoring platform. It covers payment-related security events and treats abnormal checkout activity as potential live threats.

**Key Principles:**
- **Speed**: Respond within defined SLAs
- **Thoroughness**: Document everything
- **Communication**: Keep stakeholders informed
- **Learning**: Conduct post-incident reviews

---

## Incident Severity Levels

| Level | Description | Response Time | Examples |
|-------|-------------|---------------|----------|
| **CRITICAL** | Confirmed breach, data exfiltration, or payment fraud in progress | **15 minutes** | Active payment fraud, database breach, ransomware |
| **HIGH** | Likely security incident requiring immediate attention | **1 hour** | Brute force attacks, privilege escalation, price tampering |
| **MEDIUM** | Suspicious activity requiring investigation | **4 hours** | Failed login patterns, coupon exploitation attempts |
| **LOW** | Anomalous behavior for monitoring | **24 hours** | Single unusual transaction, off-hours access |

---

## Detection → Triage → Containment Process

### Phase 1: DETECTION (Automated)

**Tools:**
- Selenium security tests (20+ scenarios)
- SQL security event database
- Python analytics engine
- PowerShell monitoring scripts

**Triggers:**
- Failed authentication attempts (>5 in 30 min)
- Transaction amount tampering detected
- Privilege escalation attempts
- Session hijacking indicators
- Abnormal checkout patterns

**Automated Actions:**
1. Log security event to database
2. Run pattern analysis
3. Generate incident report
4. Create JIRA ticket
5. Send notifications

### Phase 2: TRIAGE (Manual Review)

**Initial Assessment (First 15 minutes):**

```
□ Review incident ticket in JIRA
□ Check automated analysis report
□ Verify false positive likelihood
□ Assess severity level
□ Identify affected systems/users
□ Document initial findings
```

**Investigation Checklist:**

```sql
-- Check user authentication history
SELECT * FROM authentication_attempts 
WHERE username = '[USER]' 
ORDER BY attempt_timestamp DESC LIMIT 100;

-- Review security events for this user
SELECT * FROM security_events 
WHERE username = '[USER]' 
  AND timestamp > datetime('now', '-24 hours');

-- Analyze transaction anomalies
SELECT * FROM transaction_anomalies 
WHERE username = '[USER]' 
  AND detection_timestamp > datetime('now', '-7 days');
```

**PowerShell Investigation:**
```powershell
# Check user login history
Get-WinEvent -FilterHashtable @{
    LogName='Security'; 
    ID=4624,4625; 
    StartTime=(Get-Date).AddDays(-1)
} | Where-Object {$_.Message -like "*USERNAME*"}

# Check for privilege changes
Get-WinEvent -FilterHashtable @{
    LogName='Security'; 
    ID=4672,4673
}
```

### Phase 3: CONTAINMENT (Immediate Actions)

Based on incident type, execute appropriate containment:

**For Authentication Attacks:**
```
1. Block suspicious IP addresses
2. Force password reset for affected accounts
3. Implement rate limiting
4. Enable CAPTCHA
5. Invalidate all sessions for affected users
```

**For Payment Tampering:**
```
1. Halt affected transactions
2. Review transaction logs
3. Verify payment gateway integrity
4. Revalidate all pending orders
5. Notify payment processor if necessary
```

**For Session Hijacking:**
```
1. Invalidate all sessions for affected user
2. Force logout across all devices
3. Review session security settings
4. Check for cookie theft indicators
5. Enable multi-factor authentication
```

---

## Incident Types & Response Procedures

### 1. BRUTE FORCE ATTACK

**Detection Criteria:**
- 10+ failed login attempts in 30 minutes
- Failed attempts across multiple usernames from same IP
- Credential stuffing patterns detected

**Response Steps:**

```yaml
Severity: HIGH
Response Time: 1 hour

Immediate Actions:
  1. Block attacking IP address(es) at firewall
  2. Implement progressive rate limiting
  3. Enable CAPTCHA on login page
  4. Notify affected users if accounts compromised
  
Investigation:
  5. Review authentication logs for pattern
  6. Check if any attempts were successful
  7. Identify attack vector (web, API, mobile)
  8. Determine if part of larger campaign
  
Remediation:
  9. Force password reset for targeted accounts
  10. Implement account lockout policy
  11. Add IP to permanent blocklist if appropriate
  12. Update WAF rules
  
Documentation:
  13. Update JIRA ticket with findings
  14. Document attack patterns
  15. Create IOC (Indicators of Compromise) list
```

**SQL Queries for Investigation:**
```sql
-- Find brute force patterns
SELECT ip_address, username, COUNT(*) as attempts,
       MIN(attempt_timestamp) as first_attempt,
       MAX(attempt_timestamp) as last_attempt
FROM authentication_attempts
WHERE success = 0
  AND attempt_timestamp > datetime('now', '-2 hours')
GROUP BY ip_address, username
HAVING COUNT(*) >= 10
ORDER BY attempts DESC;
```

---

### 2. PAYMENT AMOUNT TAMPERING

**Detection Criteria:**
- Price discrepancy between cart and checkout
- Negative amounts submitted
- Decimal precision exploitation
- Currency conversion bypass

**Response Steps:**

```yaml
Severity: CRITICAL
Response Time: 15 minutes

Immediate Actions:
  1. Halt affected transaction immediately
  2. Freeze affected user account
  3. Review all recent transactions from this user
  4. Check payment gateway logs
  
Investigation:
  5. Analyze transaction anomaly details
  6. Review original vs modified amounts
  7. Identify tampering method (DOM, API, other)
  8. Check for similar patterns from other users
  
Remediation:
  9. Refund if fraudulent payment processed
  10. Strengthen server-side validation
  11. Implement additional integrity checks
  12. Update payment processing logic
  
Financial Impact:
  13. Calculate monetary loss
  14. Document for insurance/legal
  15. Report to payment processor if required
```

**Investigation Commands:**
```sql
-- Find all tampering attempts
SELECT * FROM transaction_anomalies
WHERE anomaly_type = 'PRICE_TAMPERING'
  AND detection_timestamp > datetime('now', '-24 hours')
ORDER BY ABS(modified_amount - original_amount) DESC;
```

---

### 3. PRIVILEGE ESCALATION ATTEMPT

**Detection Criteria:**
- Unauthorized admin access attempts
- Permission boundary violations
- Role manipulation attempts

**Response Steps:**

```yaml
Severity: HIGH
Response Time: 1 hour

Immediate Actions:
  1. Revoke user's current permissions
  2. Terminate all active sessions
  3. Lock account pending investigation
  4. Alert security team
  
Investigation:
  5. Review user's activity history
  6. Check for account compromise indicators
  7. Analyze how escalation was attempted
  8. Identify vulnerability exploited
  
Remediation:
  9. Patch identified vulnerability
  10. Audit all user permissions
  11. Implement additional access controls
  12. Review and harden RBAC policies
```

---

### 4. SESSION HIJACKING

**Detection Criteria:**
- Session reuse after logout
- Concurrent sessions from different locations
- Session cookie theft indicators

**Response Steps:**

```yaml
Severity: HIGH
Response Time: 1 hour

Immediate Actions:
  1. Invalidate all sessions for affected user
  2. Force re-authentication
  3. Block suspicious IP if identified
  4. Enable session monitoring
  
Investigation:
  5. Review session lifecycle
  6. Check for XSS vulnerabilities
  7. Verify HttpOnly and Secure flags on cookies
  8. Analyze session fixation possibilities
  
Remediation:
  9. Implement stronger session management
  10. Add session binding (IP, User-Agent)
  11. Reduce session timeout
  12. Enable MFA for sensitive operations
```

---

### 5. COUPON/DISCOUNT EXPLOITATION

**Detection Criteria:**
- Multiple coupon stacking
- Expired coupon usage
- Discount manipulation
- Repeated coupon abuse

**Response Steps:**

```yaml
Severity: MEDIUM
Response Time: 4 hours

Immediate Actions:
  1. Cancel fraudulent orders
  2. Flag user account
  3. Review coupon redemption logs
  
Investigation:
  4. Identify exploited vulnerability
  5. Calculate financial impact
  6. Check for automated abuse
  7. Review coupon validation logic
  
Remediation:
  8. Fix coupon validation rules
  9. Implement one-time use enforcement
  10. Add rate limiting to coupon application
  11. Improve expiration checking
```

---

## Escalation Matrix

| Incident Type | Initial Responder | Escalate To | Escalation Trigger |
|---------------|-------------------|-------------|-------------------|
| Brute Force | Security Analyst | Security Manager | >100 attempts or successful breach |
| Payment Fraud | Fraud Analyst | CFO + Legal | >$1000 loss or multiple incidents |
| Data Breach | Security Team | CISO + Legal + PR | Any confirmed data exfiltration |
| DDoS Attack | Network Ops | Security Manager | >30 min downtime |
| Privilege Escalation | Security Analyst | CISO | Successful escalation confirmed |

---

## Communication Templates

### Internal Incident Notification

```
Subject: [SECURITY INCIDENT] [SEVERITY] - Brief Description

Incident ID: [JIRA-XXX]
Severity: [HIGH/CRITICAL/MEDIUM]
Detection Time: [YYYY-MM-DD HH:MM UTC]
Status: [INVESTIGATING/CONTAINED/RESOLVED]

SUMMARY:
[Brief description of what happened]

IMPACT:
- Affected Systems: [List]
- Affected Users: [Count/List]
- Financial Impact: [If applicable]

CURRENT STATUS:
[What actions have been taken]

NEXT STEPS:
[What will happen next]

Contact: [Incident Commander]
```

### User Notification (Security Incident)

```
Subject: Important Security Notice - Action Required

Dear [User],

We detected unusual activity on your account and have taken
precautionary measures to protect your information.

WHAT HAPPENED:
We noticed [brief, non-technical explanation]

WHAT WE'VE DONE:
- Secured your account
- Reviewed recent transactions
- Blocked suspicious activity

WHAT YOU NEED TO DO:
1. Reset your password immediately
2. Review your recent transactions
3. Enable two-factor authentication

If you have questions, contact our security team at security@example.com

Thank you for your attention to this matter.

Security Team
```

---

## Post-Incident Review Template

**To be completed within 48 hours of incident resolution**

```markdown
# Post-Incident Review: [Incident ID]

## Incident Summary
- **Date/Time:** 
- **Duration:** 
- **Severity:** 
- **Type:** 

## Timeline
- **Detection:** [When and how detected]
- **Response Initiated:** [When team notified]
- **Contained:** [When threat contained]
- **Resolved:** [When fully resolved]

## Root Cause
[Detailed analysis of what caused the incident]

## Impact Assessment
- **Users Affected:** 
- **Systems Affected:** 
- **Financial Impact:** 
- **Reputational Impact:** 

## What Went Well
- [List positive aspects of response]

## What Could Be Improved
- [Areas for improvement]

## Action Items
- [ ] [Specific remediation tasks]
- [ ] [Process improvements]
- [ ] [Tool/technology enhancements]

## Lessons Learned
[Key takeaways for future incidents]
```

---

## Appendix: Key Contacts

| Role | Contact | Phone | Email |
|------|---------|-------|-------|
| Security Manager | [Name] | [Number] | [Email] |
| CISO | [Name] | [Number] | [Email] |
| Legal | [Name] | [Number] | [Email] |
| PR/Communications | [Name] | [Number] | [Email] |
| Payment Processor | [Company] | [Number] | [Email] |

---

**Last Updated:** [Date]
**Version:** 1.0
**Owner:** Security Team
