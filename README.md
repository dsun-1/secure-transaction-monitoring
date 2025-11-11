# Secure Transaction Monitoring

End-to-end security testing and incident response platform for e-commerce payment systems. Automates attack simulation, event logging, threat detection, and JIRA ticket generation.

## How It Works

```
Attack Simulation → Event Logging → Pattern Detection → Incident Response
    (Selenium)         (H2 DB)          (Python)           (JIRA API)
```

1. **Selenium tests** simulate 7 critical attack vectors (OWASP Top 10 coverage)
2. **Security events** logged to H2 database with indexed tables
3. **Python analyzer** detects patterns (5+ failed logins, price tampering, timing anomalies)
4. **JIRA tickets** auto-generated with severity mapping and investigation steps
5. **GitHub Actions** runs full pipeline nightly + on every push

## Running It

### Quick Start
```bash
# 1. Start the application
cd ecommerce-app
mvn spring-boot:run
# App runs on http://localhost:8080

# 2. Run security tests (separate terminal)
cd security-tests
mvn test
# 7 tests execute in ~16 seconds
# Logs saved to data/security-events.mv.db

# 3. Analyze threats and generate JIRA tickets
cd scripts/python
python security_analyzer.py
# Creates incident report JSON

# Optional: Test JIRA integration locally
$env:JIRA_URL="https://secure-transaction.atlassian.net"
$env:JIRA_USERNAME="your-email@example.com"
$env:JIRA_API_TOKEN="your-api-token"
$env:JIRA_PROJECT_KEY="KAN"
.\test-jira.ps1
```

### What You'll See
- **Web UI:** Product catalog, shopping cart, checkout flow at http://localhost:8080
- **Test Output:** TestNG reports in `security-tests/target/surefire-reports/`
- **Database:** H2 file at `ecommerce-app/data/security-events.mv.db` (view with H2 Console)
- **Incidents:** JSON reports with severity, affected users, timestamps
- **JIRA Tickets:** Auto-created with priority mapping (HIGH→Highest, MEDIUM→High)

## What's Included

### Security Testing (7 Core Tests - OWASP Top 10 Coverage)
- ✅ **Brute Force Detection** - Failed login attempts, account lockout (OWASP A07)
- ✅ **Session Hijacking** - Cookie theft, session fixation (OWASP A07)
- ✅ **SQL Injection** - Database attack patterns (OWASP A03)
- ✅ **Payment Tampering** - Price manipulation, amount modification (OWASP A01, A04)
- ✅ **Coupon Exploitation** - Authorization bypass, business logic abuse (OWASP A01)
- ✅ **REST API Security** - Authentication, rate limiting, data exposure (OWASP A01, A05)
- ✅ **Security Event Logging** - Real-time monitoring, anomaly detection (OWASP A09)

### Automated Incident Response
- **SQL Database Logging** - 3 tables (security_events, authentication_attempts, transaction_anomalies), 8 indexes
- **Python Threat Analyzer** - Pattern detection (brute force, account enumeration, privilege escalation, transaction anomalies, timing attacks)
- **JIRA Integration** - Auto-generates tickets with severity mapping (HIGH→Highest, MEDIUM→High, LOW→Medium)
- **PowerShell Monitor** - Windows security events, process monitoring, failed login detection
- **GitHub Actions Pipeline** - Nightly runs (2 AM UTC), SpotBugs static analysis, OWASP Dependency-Check

### Tech Stack
**Backend:** Java 21, Spring Boot 3.5.0, Spring Security 6.x  
**Testing:** Selenium WebDriver 4.16.1, TestNG 7.9.0, RestAssured 5.4.0  
**Security:** SpotBugs 4.8.3.1 + FindSecBugs 1.13.0, OWASP Dependency-Check 9.0.9  
**Database:** H2 2.3.232 (file-based, 45KB with test data)  
**Analysis:** Python 3.11, Pandas, Requests  
**CI/CD:** Maven 3.9+, GitHub Actions, JIRA REST API  
**Monitoring:** PowerShell 5.1+, Windows Event Logs

---

## Key Features

### 🔐 Comprehensive Attack Simulation
- **Authentication Testing:** Brute force detection with configurable thresholds (5+ attempts = HIGH severity)
- **Session Management:** Cookie manipulation, hijacking detection, secure session handling
- **Payment Security:** Amount tampering validation, negative values, zero-dollar transactions
- **Business Logic:** Coupon abuse, discount stacking, authorization bypass
- **Input Validation:** SQL injection patterns, XSS payloads, command injection attempts
- **API Security:** 7 REST endpoint tests covering auth, rate limiting, data exposure

### 📊 Real-Time Monitoring & Analytics
- **Structured Logging:** 3 normalized tables with foreign key relationships
- **Indexed Queries:** 8 database indexes for fast pattern detection
- **Threat Correlation:** Groups related events (e.g., 5 failed logins from same IP = brute force)
- **Severity Classification:** Automatic HIGH/MEDIUM/LOW assignment based on CVSS-like criteria
- **Time-Series Analysis:** Detects suspicious timing patterns (rapid requests, off-hours activity)

### 🎫 Automated Incident Response
- **JIRA REST API Integration:** Creates tickets in Kanban/Scrum projects
- **Smart Priority Mapping:** HIGH severity → Highest priority, MEDIUM → High, LOW → Medium
- **Rich Context:** Tickets include username, IP, timestamps, attack vectors, investigation steps
- **Deduplication:** Prevents ticket spam for repeated incidents
- **Configurable:** Environment variables for URL, credentials, project keys

### 🚀 CI/CD Pipeline
- **GitHub Actions:** 302-line workflow with 7 jobs
- **Scheduled Runs:** Nightly at 2 AM UTC + on every push/PR
- **Static Analysis:** SpotBugs with 135+ security rules (SQL injection, XSS, weak crypto detection)
- **Dependency Scanning:** OWASP Dependency-Check for CVE detection
- **Artifact Uploads:** Test reports, security scans, incident JSONs preserved for 90 days

---

## Project Stats

- **Lines of Code:** ~3,500+ (Java, Python, PowerShell combined)
- **Test Coverage:** 7 fully automated security scenarios
- **Build Time:** ~45 seconds (clean compile)
- **Test Execution:** ~16 seconds (7 tests, headless Chrome)
- **Database Schema:** 3 tables, 8 indexes, ~45KB with test data
- **CI/CD Workflow:** 302 lines, 7 jobs, runs in ~8 minutes
- **OWASP Coverage:** 5 of 10 top risks (A01, A03, A04, A07, A09)

---

## Development Timeline

**Phase 1 (Dec 2024):** Core application + test framework  
**Phase 2 (Jan 2025):** Security tests + database logging  
**Phase 3 (Feb 2025):** Python analyzer + JIRA integration  
**Phase 4 (Nov 2025):** CI/CD pipeline + SpotBugs migration

---

## License & Purpose

Built as a **portfolio project** to demonstrate security testing automation and incident response capabilities. Not intended for production use without additional hardening.
