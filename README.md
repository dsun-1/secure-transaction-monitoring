# Secure Transaction Monitoring & Incident Response Platform

[![CI/CD Pipeline](https://github.com/username/secure-transac/workflows/Security%20Test%20Suite/badge.svg)](https://github.com/username/secure-transac/actions)
[![Security Scan](https://img.shields.io/badge/security-monitored-green.svg)](https://github.com/username/secure-transac)

## 🎯 Project Overview

An end-to-end testing and monitoring environment for a mock e-commerce checkout flow, emphasizing both reliability and security. This platform automates security testing, monitors transaction anomalies, detects potential threats, and generates actionable incident reports.

**Duration:** December 2024 – February 2025

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                  Mock E-Commerce Platform                    │
│        (Spring Boot + Thymeleaf + H2 Database)              │
└─────────────┬───────────────────────────────────────────────┘
              │
┌─────────────▼───────────────────────────────────────────────┐
│           Automated Security Test Suite                      │
│     (Selenium WebDriver + TestNG + Maven)                   │
│  • Login Abuse Tests    • Cart Tampering                    │
│  • Payment Validation   • Session Security                  │
│  • Coupon Edge Cases    • SQL Injection Tests              │
└─────────────┬───────────────────────────────────────────────┘
              │
┌─────────────▼───────────────────────────────────────────────┐
│         Security Event Collection Layer                      │
│              (SQL Database + Logging)                        │
│  • Authentication Events  • Failed Login Attempts           │
│  • Transaction Anomalies  • Suspicious Activities           │
└─────────────┬───────────────────────────────────────────────┘
              │
┌─────────────▼───────────────────────────────────────────────┐
│        Incident Detection & Analysis Engine                  │
│          (Python + PowerShell Scripts)                       │
│  • Brute Force Detection  • Privilege Escalation            │
│  • Pattern Analysis       • Process Monitoring              │
└─────────────┬───────────────────────────────────────────────┘
              │
┌─────────────▼───────────────────────────────────────────────┐
│     Automated Reporting & Incident Response                  │
│         (GitHub Actions + JIRA Integration)                  │
│  • Nightly CI/CD Reports  • Incident Tickets                │
│  • Vulnerability Scans    • Remediation Tracking            │
└─────────────────────────────────────────────────────────────┘
```

## 🚀 Key Features

### 1. Automated Security Testing (20+ Scenarios)
- **Authentication Testing**: Login abuse, brute force attempts, session hijacking
- **Payment Security**: Invalid payment methods, amount tampering, authorization bypass
- **Business Logic**: Coupon exploitation, cart manipulation, inventory bypass
- **Input Validation**: SQL injection, XSS, CSRF protection
- **Session Management**: Session reuse, fixation, timeout validation

### 2. Real-Time Security Monitoring
- Captures authentication events and failed login patterns
- Tracks transaction anomalies and suspicious payment attempts
- Monitors privilege escalation and unauthorized access
- Logs process activities and system-level security events

### 3. Intelligent Incident Detection
- **Python Analytics Engine**: Pattern recognition, anomaly detection, threat correlation
- **PowerShell Monitoring**: Process analysis, privilege checks, system hardening validation
- **SQL Analytics**: Query-based threat detection, baseline deviation analysis

### 4. Automated Incident Response
- Generates incident tickets with full context (timestamp, user, session, root cause)
- Integrates with JIRA for ticket creation and tracking
- Publishes nightly security reports via GitHub Actions
- Maintains audit trail for compliance and forensics

### 5. Vulnerability Assessment
- Port scanning and network exposure analysis
- Credential strength validation
- Dependency vulnerability scanning (Fortify integration)
- Configuration security checks
- Documented remediation steps

## 🛠️ Technology Stack

| Category | Technologies |
|----------|-------------|
| **Backend** | Java 17, Spring Boot 3.x, Maven |
| **Testing** | Selenium WebDriver, TestNG, REST Assured |
| **Database** | H2 (embedded), SQL |
| **Scripting** | Python 3.x, PowerShell 7.x |
| **Security** | Fortify, OWASP Dependency Check |
| **CI/CD** | GitHub Actions |
| **Reporting** | Tableau, PowerBI, HTML Reports |
| **Ticketing** | JIRA REST API |

## 📦 Project Structure

```
secure-transac/
├── ecommerce-app/              # Mock e-commerce application
│   ├── src/main/java/          # Spring Boot application
│   ├── src/main/resources/     # Configuration & templates
│   └── pom.xml                 # Maven dependencies
│
├── security-tests/             # Automated security test suite
│   ├── src/test/java/          # TestNG test cases
│   ├── test-data/              # Test datasets
│   ├── testng.xml              # Test suite configuration
│   └── pom.xml                 # Test dependencies
│
├── monitoring/                 # Security monitoring components
│   ├── database/               # SQL schema & queries
│   ├── python-analytics/       # Python analysis scripts
│   ├── powershell-scripts/     # PowerShell monitoring
│   └── fortify-config/         # Fortify scan configurations
│
├── incident-response/          # Incident response automation
│   ├── playbooks/              # Response playbooks
│   ├── ticket-generator/       # JIRA integration
│   └── reports/                # Generated reports
│
├── .github/                    # GitHub Actions workflows
│   └── workflows/              # CI/CD pipelines
│
├── docs/                       # Documentation
│   ├── architecture.md         # System architecture
│   ├── security-controls.md    # Security controls catalog
│   └── vulnerability-reports/  # Vulnerability assessments
│
└── scripts/                    # Utility scripts
    ├── setup.ps1               # Environment setup
    └── run-tests.sh            # Test execution
```

## 🚦 Quick Start

### Prerequisites
- Java 17+
- Maven 3.8+
- Python 3.9+
- PowerShell 7.x
- Chrome/ChromeDriver (for Selenium)
- Git

### Setup Instructions

1. **Clone the repository**
   ```bash
   git clone https://github.com/username/secure-transac.git
   cd secure-transac
   ```

2. **Run setup script**
   ```powershell
   .\scripts\setup.ps1
   ```

3. **Start the e-commerce application**
   ```bash
   cd ecommerce-app
   mvn spring-boot:run
   ```

4. **Run security tests**
   ```bash
   cd security-tests
   mvn clean test
   ```

5. **Execute monitoring scripts**
   ```powershell
   .\monitoring\powershell-scripts\monitor-security-events.ps1
   ```

## 📊 Security Test Coverage

| Category | Test Count | Coverage |
|----------|-----------|----------|
| Authentication | 5 | 100% |
| Authorization | 4 | 100% |
| Payment Processing | 6 | 95% |
| Cart & Checkout | 3 | 100% |
| Session Management | 3 | 100% |
| Input Validation | 4 | 90% |
| **Total** | **25** | **97%** |

## 🔒 Security Controls Implemented

1. **Authentication Hardening**
   - Account lockout after 5 failed attempts
   - Password complexity requirements
   - Session timeout (15 minutes)
   - Multi-factor authentication ready

2. **Transaction Security**
   - Amount tampering detection
   - Authorization validation
   - Duplicate transaction prevention
   - Real-time fraud scoring

3. **Monitoring & Detection**
   - Failed login tracking
   - Brute force detection (5 attempts in 5 minutes)
   - Privilege escalation monitoring
   - Anomalous transaction patterns

4. **Incident Response**
   - Automated ticket creation
   - Root cause analysis
   - Containment procedures
   - Post-incident review process

## 📈 Incident Response Workflow

```
┌──────────────┐
│  Detection   │  ← Automated monitoring detects anomaly
└──────┬───────┘
       │
┌──────▼───────┐
│   Triage     │  ← Python/PowerShell analyze severity
└──────┬───────┘
       │
┌──────▼───────┐
│ Containment  │  ← Auto-disable compromised accounts/sessions
└──────┬───────┘
       │
┌──────▼───────┐
│  Analysis    │  ← Root cause investigation
└──────┬───────┘
       │
┌──────▼───────┐
│ Remediation  │  ← Apply security patches/controls
└──────┬───────┘
       │
┌──────▼───────┐
│  Reporting   │  ← Generate JIRA ticket + CI/CD report
└──────────────┘
```

## 📝 Sample Incident Ticket

```
Incident ID: INC-2025-0042
Severity: HIGH
Detected: 2025-02-15 03:42:15 UTC

Title: Brute Force Attack Detected - Account: admin@example.com

Description:
Multiple failed login attempts detected from IP 192.168.1.100
- Attempt count: 12 in 3 minutes
- Pattern: Sequential password guessing
- User-Agent: Python-requests/2.31.0

Impact: Potential account compromise, authentication bypass

Root Cause: No rate limiting on login endpoint

Recommended Actions:
1. Block source IP: 192.168.1.100
2. Reset admin account password
3. Implement rate limiting (5 attempts per 5 minutes)
4. Enable MFA for admin accounts
5. Review logs for successful breaches

Status: OPEN
Assigned: Security Team
```

## 🔍 Vulnerability Assessment Results

| Vulnerability | Severity | Status | Remediation |
|--------------|----------|--------|-------------|
| Weak password policy | HIGH | Fixed | Implemented complexity rules |
| Open debug port (8080) | MEDIUM | Fixed | Disabled in production |
| Outdated Spring version | HIGH | Fixed | Updated to 3.2.2 |
| Missing CSRF tokens | CRITICAL | Fixed | Enabled Spring Security CSRF |
| SQL injection risk | HIGH | Fixed | Parameterized queries |

## 📚 Documentation

- [Incident Response Playbook](./incident-response/playbooks/payment-security-playbook.md)
- [Security Controls Catalog](./docs/security-controls.md)
- [Vulnerability Assessment Report](./docs/vulnerability-reports/assessment-2025-02.md)
- [Test Suite Documentation](./security-tests/README.md)

## 🎓 Skills Demonstrated

✅ **Security Testing**: Automated 25+ security scenarios covering OWASP Top 10  
✅ **Incident Detection**: Pattern analysis, anomaly detection, threat correlation  
✅ **Vulnerability Assessment**: Scanning, documentation, remediation tracking  
✅ **Monitoring & Logging**: Real-time event capture, SQL analytics  
✅ **Automation**: CI/CD integration, automated reporting, ticket generation  
✅ **Tool Proficiency**: Java, Python, PowerShell, SQL, Selenium, Maven, Fortify  
✅ **Communication**: Structured reporting, playbook creation, technical documentation  

## 🤝 Contributing

This is a portfolio/learning project. Feedback and suggestions welcome!

## 📄 License

MIT License - See LICENSE file for details

## 👤 Author

**Your Name**
- Portfolio: [your-portfolio.com](https://your-portfolio.com)
- LinkedIn: [linkedin.com/in/yourprofile](https://linkedin.com/in/yourprofile)
- GitHub: [@yourusername](https://github.com/yourusername)

---

*This project demonstrates practical cybersecurity skills applicable to financial services, e-commerce, and transaction security domains.*
