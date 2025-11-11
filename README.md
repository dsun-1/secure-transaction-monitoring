# Secure Transaction Monitoring

Enterprise-grade security testing and incident response platform for e-commerce payment systems with **SIEM integration**. Automates attack simulation, real-time threat detection, event correlation, and multi-channel alerting.

## 🎯 What Makes This Special

- **100% OWASP Top 10 2021 Coverage** - All 10 categories addressed with automated testing
- **Enterprise SIEM Integration** - Real-time event streaming to Elasticsearch/Splunk
- **Multi-Channel Alerting** - Slack, Email, PagerDuty for critical security events
- **Automated Threat Correlation** - ML-style pattern detection (brute force, distributed attacks, privilege escalation)
- **Production-Ready Architecture** - Async processing, scheduled tasks, externalized configuration
- **Full Stack Security** - From input validation to session management to payment processing

## How It Works

```
Attack Simulation → Event Logging → SIEM Integration → Threat Correlation → Multi-Channel Alerts
    (Selenium)      (H2 + Spring)    (Elasticsearch)     (Pattern Detection)    (Slack/Email/PagerDuty)
```

1. **Security tests** simulate 15+ attack vectors across OWASP Top 10
2. **Events automatically logged** to database and streamed to SIEM in real-time
3. **SIEM systems** (Elasticsearch/Splunk) index and aggregate security events
4. **Correlation engine** analyzes patterns every 5 minutes (brute force, distributed attacks)
5. **Alert manager** sends notifications via Slack/Email/PagerDuty for HIGH/CRITICAL events
6. **JIRA tickets** auto-generated for incident tracking and remediation

## Running It

### Quick Start
```powershell
# 1. Start the application
cd ecommerce-app
mvn spring-boot:run
# App runs on http://localhost:8080

# 2. Run security tests (separate terminal)
cd security-tests
mvn test
# 15 comprehensive security tests execute
# Events automatically logged and sent to SIEM (if enabled)

# 3. View SIEM integration test results
cd ecommerce-app
mvn test -Dtest=SiemIntegrationTest
# Verifies: Event logging, SIEM integration, alert triggering

# 4. Analyze threats and generate JIRA tickets
cd scripts/python
python security_analyzer.py
# Creates incident report JSON with detected patterns

# 5. Optional: Test JIRA integration
$env:JIRA_URL="https://secure-transaction.atlassian.net"
$env:JIRA_USERNAME="your-email@example.com"
$env:JIRA_API_TOKEN="your-api-token"
$env:JIRA_PROJECT_KEY="KAN"
.\test-jira.ps1
```

### Production SIEM Setup (Optional)
To enable enterprise SIEM features, see **[SIEM Setup Guide](docs/SIEM_SETUP_GUIDE.md)** for:
- Elasticsearch/ELK Stack configuration
- Splunk HEC integration
- Slack webhook setup
- Email SMTP configuration
- PagerDuty API integration

### What You'll See
- **Web UI:** Full e-commerce flow (products → cart → checkout) at http://localhost:8080
- **Authentication:** BCrypt-secured login with session management
- **Shopping Cart:** Add/update/remove items with real-time calculations
- **Checkout:** Payment validation with security event logging
- **Test Reports:** TestNG reports in `security-tests/target/surefire-reports/`
- **Database:** H2 file at `ecommerce-app/data/security-events.mv.db`
- **SIEM Events:** Real-time streaming to Elasticsearch/Splunk (if enabled)
- **Security Alerts:** 🚨 Console logs + Slack/Email/PagerDuty for HIGH/CRITICAL events
- **Threat Detection:** Scheduled correlation analysis every 5 minutes
- **JIRA Tickets:** Auto-created with priority mapping and investigation steps

## What's Included

### 🔒 Complete E-Commerce Application
- **User Authentication** - BCrypt password hashing, secure session management, login/logout
- **Product Catalog** - Browse products with details, images, pricing
- **Shopping Cart** - Add/update/remove items, real-time price calculations
- **Checkout System** - Payment validation, order processing, confirmation
- **Security Events** - Comprehensive logging of all security-relevant actions
- **SIEM Integration** - Real-time event streaming to enterprise monitoring systems

### 🛡️ Security Testing Suite (15 Tests - OWASP Top 10 2021: 10/10 Coverage)

#### A01: Broken Access Control (3 tests)
- ✅ **Coupon Exploitation Test** - Authorization bypass, business logic abuse
- ✅ **Privilege Escalation Test** - Unauthorized access attempts, role validation
- ✅ **REST API Authorization Test** - Endpoint access control, token validation

#### A02: Cryptographic Failures (2 tests)
- ✅ **Weak Encryption Test** - Algorithm strength validation, key management
- ✅ **Sensitive Data Exposure Test** - PII/PCI data protection, transmission security

#### A03: Injection (2 tests)
- ✅ **SQL Injection Test** - Database attack patterns, parameterized queries
- ✅ **Command Injection Test** - OS command injection prevention

#### A04: Insecure Design (2 tests)
- ✅ **Payment Tampering Test** - Price manipulation, amount validation
- ✅ **Business Logic Test** - Workflow abuse, state manipulation

#### A05: Security Misconfiguration (1 test)
- ✅ **Security Headers Test** - HSTS, CSP, X-Frame-Options, X-Content-Type-Options

#### A06: Vulnerable Components (1 test)
- ✅ **Dependency Vulnerability Test** - CVE scanning, outdated library detection

#### A07: Authentication Failures (2 tests)
- ✅ **Brute Force Detection Test** - Failed login attempts, account lockout
- ✅ **Session Hijacking Test** - Cookie theft, session fixation, secure session handling

#### A08: Data Integrity Failures (1 test)
- ✅ **Transaction Integrity Test** - Checksum validation, data tampering detection

#### A09: Logging & Monitoring Failures (1 test)
- ✅ **Security Event Logging Test** - Real-time monitoring, anomaly detection, event correlation

#### A10: Server-Side Request Forgery (1 test)
- ✅ **SSRF Prevention Test** - URL validation, internal network protection

### 🔍 Enterprise SIEM Integration (NEW!)

#### Real-Time Event Streaming
- **SiemIntegrationService** - Async event forwarding to Elasticsearch/Splunk
- **Elasticsearch Integration** - JSON event indexing with timestamp-based indexes
- **Splunk HEC Integration** - HTTP Event Collector with source type mapping
- **Automatic Triggering** - Every security event automatically sent to SIEM
- **High-Severity Detection** - CRITICAL/HIGH events trigger immediate alerts

#### Multi-Channel Alerting
- **AlertManagerService** - Async alert distribution to multiple channels
- **Slack Integration** - Webhook-based notifications with emoji indicators (🚨)
- **Email Alerts** - SMTP-based notifications with HTML formatting
- **PagerDuty Integration** - API v2 incident creation for on-call teams
- **Formatted Messages** - Structured alerts with severity, event type, timestamp, user, IP

#### Automated Threat Correlation
- **SiemCorrelationService** - Scheduled analysis runs every 5 minutes
- **Brute Force Detection** - 5+ failed logins from same IP within 15 minutes
- **Distributed Attack Detection** - 10+ security events from different IPs within 15 minutes
- **Privilege Escalation Detection** - 3+ unauthorized access attempts within 15 minutes
- **Alert Generation** - Detected patterns automatically create high-severity alerts

#### Configuration Management
- **Externalized Config** - All SIEM settings in `application.properties`
- **Toggle Features** - Enable/disable integrations without code changes
- **Async Processing** - Thread pool (5-10 threads) for non-blocking operations
- **Production Ready** - All integrations disabled by default, enable as needed

### 📊 Automated Incident Response
- **SQL Database Logging** - 3 tables (security_events, authentication_attempts, transaction_anomalies), 8 indexes
- **Enhanced Queries** - Time-based event retrieval, IP-based correlation, event type filtering
- **Python Threat Analyzer** - Pattern detection (brute force, account enumeration, privilege escalation, transaction anomalies, timing attacks)
- **JIRA Integration** - Auto-generates tickets with severity mapping (HIGH→Highest, MEDIUM→High, LOW→Medium)
- **PowerShell Monitor** - Windows security events, process monitoring, failed login detection
- **GitHub Actions Pipeline** - Nightly runs (2 AM UTC), SpotBugs static analysis, OWASP Dependency-Check

### 🛠️ Tech Stack
**Backend:** Java 21, Spring Boot 3.5.0 (Spring Framework 6.2.x), Spring Security 6.x  
**Testing:** Selenium WebDriver 4.16.1, TestNG 7.9.0, RestAssured 5.4.0, JUnit 5  
**Security:** SpotBugs 4.8.3.1 + FindSecBugs 1.13.0, OWASP Dependency-Check 9.0.9  
**Database:** H2 2.3.232 (file-based, enhanced with correlation queries)  
**SIEM:** Elasticsearch REST API, Splunk HEC, async processing with @EnableAsync  
**Alerting:** Slack webhooks, SMTP email, PagerDuty API v2, scheduled tasks with @EnableScheduling  
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
- **API Security:** 15 REST endpoint tests covering auth, rate limiting, data exposure
- **Cryptography:** Weak algorithm detection, key management validation
- **SSRF Prevention:** URL validation, internal network protection

### 📊 Real-Time Monitoring & Analytics
- **Structured Logging:** 3 normalized tables with foreign key relationships
- **Indexed Queries:** 8 database indexes for fast pattern detection
- **Time-Based Correlation:** Query events by timestamp ranges for pattern analysis
- **IP-Based Tracking:** Group events by IP address for distributed attack detection
- **Threat Correlation:** Groups related events (e.g., 5 failed logins from same IP = brute force)
- **Severity Classification:** Automatic HIGH/MEDIUM/LOW assignment based on CVSS-like criteria
- **Time-Series Analysis:** Detects suspicious timing patterns (rapid requests, off-hours activity)
- **SIEM Streaming:** Real-time event forwarding to Elasticsearch/Splunk with async processing

### 🚨 Enterprise Alerting & Response
- **Multi-Channel Notifications:** Slack, Email, PagerDuty for different severity levels
- **Immediate Alert Triggering:** HIGH/CRITICAL events automatically trigger AlertManager
- **Formatted Alert Messages:** Structured alerts with severity, event type, timestamp, user, IP, description
- **Scheduled Correlation Analysis:** Every 5 minutes, analyzes patterns and generates alerts
- **Threat Pattern Detection:** Brute force (5/15min), distributed attacks (10 IPs/15min), privilege escalation (3/15min)
- **Async Processing:** Non-blocking alert distribution with dedicated thread pool
- **Configuration Flexibility:** Enable/disable channels individually without code changes

### 🎫 Automated Incident Response
- **JIRA REST API Integration:** Creates tickets in Kanban/Scrum projects
- **Smart Priority Mapping:** HIGH severity → Highest priority, MEDIUM → High, LOW → Medium
- **Rich Context:** Tickets include username, IP, timestamps, attack vectors, investigation steps
- **Deduplication:** Prevents ticket spam for repeated incidents
- **Configurable:** Environment variables for URL, credentials, project keys

### 🚀 CI/CD Pipeline
- **GitHub Actions:** Comprehensive workflow with multiple jobs
- **Scheduled Runs:** Nightly at 2 AM UTC + on every push/PR
- **Static Analysis:** SpotBugs with 135+ security rules (SQL injection, XSS, weak crypto detection)
- **Dependency Scanning:** OWASP Dependency-Check for CVE detection
- **Test Execution:** Automated security test runs with report generation
- **Artifact Uploads:** Test reports, security scans, incident JSONs preserved for 90 days

---

## 📈 Project Stats

### Code Metrics
- **Total Lines of Code:** ~5,000+ (Java, Python, PowerShell combined)
- **Java Source Files:** 30+ classes across main and test packages
- **Test Coverage:** 15 fully automated security scenarios (100% OWASP Top 10 2021)
- **SIEM Services:** 3 core services (Integration, Alerting, Correlation)
- **Configuration:** 50+ externalized properties for production flexibility

### Performance
- **Build Time:** ~45 seconds (clean compile)
- **Test Execution:** Varies by test suite (individual tests 2-10 seconds each)
- **SIEM Processing:** Async with dedicated thread pool (5-10 threads, 100 queue capacity)
- **Correlation Analysis:** Runs every 5 minutes via @Scheduled task
- **Database Size:** ~45KB with test data (H2 file-based storage)

### Security Coverage
- **OWASP Top 10 2021:** 10/10 categories covered (100% coverage)
  - A01 Broken Access Control ✅
  - A02 Cryptographic Failures ✅
  - A03 Injection ✅
  - A04 Insecure Design ✅
  - A05 Security Misconfiguration ✅
  - A06 Vulnerable Components ✅
  - A07 Authentication Failures ✅
  - A08 Data Integrity Failures ✅
  - A09 Logging & Monitoring Failures ✅
  - A10 Server-Side Request Forgery ✅
- **SpotBugs Rules:** 135+ security-specific rules active
- **SIEM Integrations:** 3 major platforms (Elasticsearch, Splunk, custom)
- **Alert Channels:** 3 channels (Slack, Email, PagerDuty)

---

## 📚 Documentation

### Core Documentation
- **[README.md](README.md)** - This file, complete project overview
- **[PROJECT_SUMMARY.md](docs/PROJECT_SUMMARY.md)** - Detailed architecture and design decisions
- **[INTERVIEW_DEMO_GUIDE.md](docs/INTERVIEW_DEMO_GUIDE.md)** - Step-by-step demo script for presentations
- **[AUDIT_REPORT.md](docs/AUDIT_REPORT.md)** - Security audit findings and remediation
- **[INCIDENT_RESPONSE_PLAYBOOK.md](docs/INCIDENT_RESPONSE_PLAYBOOK.md)** - Response procedures for detected threats

### SIEM Documentation (NEW!)
- **[SIEM_SETUP_GUIDE.md](docs/SIEM_SETUP_GUIDE.md)** - Complete setup instructions for all SIEM integrations
- **[SIEM_IMPLEMENTATION_SUMMARY.md](docs/SIEM_IMPLEMENTATION_SUMMARY.md)** - Architecture overview and design decisions
- **[SIEM_VERIFICATION_REPORT.md](docs/SIEM_VERIFICATION_REPORT.md)** - Test results and verification evidence
- **[OWASP_TOP_10_COVERAGE.md](docs/OWASP_TOP_10_COVERAGE.md)** - Detailed mapping of tests to OWASP categories

### Integration Documentation
- **[JIRA_SETUP.md](JIRA_SETUP.md)** - JIRA API configuration and usage
- **[test-jira.ps1](test-jira.ps1)** - PowerShell script for testing JIRA integration
- **[test-jira.bat](test-jira.bat)** - Batch file wrapper for JIRA testing

---

## 🏗️ Architecture

### Application Structure
```
secure-transac/
├── ecommerce-app/          # Main Spring Boot application
│   ├── src/main/java/com/security/ecommerce/
│   │   ├── config/         # Security, SIEM, and application configuration
│   │   ├── controller/     # REST controllers (Product, User, Cart, Checkout)
│   │   ├── model/          # Domain models (User, Product, Cart, Order, SecurityEvent)
│   │   ├── repository/     # JPA repositories with enhanced queries
│   │   └── service/        # Business logic + SIEM services
│   ├── src/main/resources/
│   │   ├── application.properties  # Externalized configuration (50+ properties)
│   │   └── templates/      # Thymeleaf HTML templates
│   └── data/               # H2 database files
├── security-tests/         # TestNG security test suite
│   └── src/test/java/com/security/tests/
│       ├── auth/           # Authentication & session tests
│       ├── api/            # REST API security tests
│       ├── injection/      # SQL/Command injection tests
│       ├── payment/        # Payment security tests
│       ├── crypto/         # Cryptography tests
│       ├── integrity/      # Data integrity tests
│       └── ssrf/           # SSRF prevention tests
├── scripts/
│   ├── python/             # Security analyzer & JIRA integration
│   └── powershell/         # Windows monitoring scripts
└── docs/                   # Comprehensive documentation (8 files)
```

### SIEM Integration Flow
```
Security Event Occurs
       ↓
SecurityEventService.logEvent()
       ↓
Save to Database (SecurityEventRepository)
       ↓
SiemIntegrationService.sendToSiem() [@Async]
       ├→ Send to Elasticsearch (if enabled)
       ├→ Send to Splunk HEC (if enabled)
       └→ Check severity (HIGH/CRITICAL?)
              ↓ YES
              AlertManagerService.sendAlert() [@Async]
                   ├→ Slack webhook
                   ├→ Email SMTP
                   └→ PagerDuty API
       
SiemCorrelationService.analyzeSecurityEvents() [@Scheduled every 5min]
       ├→ detectBruteForceAttacks() [5+ fails/15min]
       ├→ detectDistributedAttacks() [10+ IPs/15min]
       └→ detectPrivilegeEscalation() [3+ unauth/15min]
              ↓ Pattern Detected
              AlertManagerService.sendAlert()
```

---

## 🚀 Development Timeline

**Phase 1 (Dec 2024):** Core application framework  
**Phase 2 (Jan 2025):** Security test suite + database logging  
**Phase 3 (Feb 2025):** Python analyzer + JIRA integration  
**Phase 4 (Nov 2025):** CI/CD pipeline + SpotBugs migration  
**Phase 5 (Nov 2025):** Spring Boot 3.5 upgrade  
**Phase 6 (Nov 2025):** Complete feature implementation (login, cart, checkout)  
**Phase 7 (Nov 2025):** Enterprise SIEM integration + multi-channel alerting  
**Phase 8 (Nov 2025):** 100% OWASP Top 10 2021 coverage achieved ✅

---

## 🧪 Testing & Verification

### Test Execution
```powershell
# Run all security tests
cd security-tests
mvn test

# Run SIEM integration tests
cd ecommerce-app
mvn test -Dtest=SiemIntegrationTest

# Run specific test class
mvn test -Dtest=BruteForceTest

# Run with verbose output
mvn test -X
```

### Test Results (Verified November 10, 2025)
- **SIEM Integration Tests:** 3/3 passed ✅
  - Services load correctly
  - Events logged to database
  - HIGH/CRITICAL events trigger alerts
- **Build Compilation:** SUCCESS (30 source files)
- **Security Test Suite:** All 15 tests implemented and functional
- **Database Queries:** Enhanced with time-based and IP-based correlation
- **Async Processing:** Thread pool configured and operational
- **Alert Triggering:** Console logs show 🚨 for critical events

---

## 🔧 Configuration

### SIEM Configuration (application.properties)
```properties
# Elasticsearch Integration
siem.elasticsearch.enabled=false
siem.elasticsearch.url=http://localhost:9200
siem.elasticsearch.username=elastic
siem.elasticsearch.password=changeme

# Splunk Integration
siem.splunk.enabled=false
siem.splunk.url=https://localhost:8088
siem.splunk.token=your-hec-token

# Alert Channels
alert.slack.enabled=false
alert.slack.webhook=https://hooks.slack.com/services/YOUR/WEBHOOK/URL

alert.email.enabled=false
alert.email.smtp-host=smtp.gmail.com
alert.email.smtp-port=587
alert.email.username=your-email@example.com
alert.email.password=your-app-password

alert.pagerduty.enabled=false
alert.pagerduty.integration-key=your-integration-key

# Async Processing
spring.task.execution.pool.core-size=5
spring.task.execution.pool.max-size=10
spring.task.execution.pool.queue-capacity=100
```

### Enabling SIEM in Production
1. Set `siem.elasticsearch.enabled=true` (or `siem.splunk.enabled=true`)
2. Configure connection details (URL, credentials, tokens)
3. Enable alert channels (Slack, Email, PagerDuty)
4. Restart application
5. Monitor logs for 🚨 SECURITY ALERT messages
6. Verify events appear in Elasticsearch/Splunk dashboards

---

## 🎯 Use Cases

### For Security Engineers
- **Penetration Testing:** Simulate attacks and observe detection capabilities
- **SIEM Tuning:** Test correlation rules and alert thresholds
- **Incident Response:** Practice response procedures with realistic scenarios
- **Compliance:** Demonstrate OWASP Top 10 coverage for audits

### For DevSecOps Teams
- **CI/CD Integration:** Automated security testing in deployment pipelines
- **Vulnerability Management:** Track and remediate security findings
- **Threat Intelligence:** Analyze attack patterns and trends
- **Alerting Validation:** Test multi-channel notification systems

### For Developers
- **Secure Coding:** Learn common vulnerabilities and prevention techniques
- **Security Testing:** Understand how to write security-focused tests
- **Event Logging:** See best practices for security event instrumentation
- **Spring Security:** Reference implementation of authentication and authorization

### For Students & Learners
- **OWASP Top 10:** Hands-on practice with all 10 categories
- **Full Stack Security:** End-to-end security from frontend to backend
- **Enterprise Patterns:** SIEM integration, async processing, correlation analysis
- **Portfolio Project:** Production-ready code for showcasing skills

---

## 🔒 Security Considerations

### Current Implementation
- ✅ BCrypt password hashing (strength 10)
- ✅ Session management with secure cookies
- ✅ Input validation and sanitization
- ✅ SQL injection prevention (parameterized queries)
- ✅ CSRF protection (Spring Security default)
- ✅ XSS prevention (Thymeleaf escaping)
- ✅ Rate limiting considerations in tests
- ✅ Security event logging for all critical actions
- ✅ SIEM integration for real-time monitoring
- ✅ Multi-channel alerting for high-severity events

### Production Hardening Recommendations
- ⚠️ Enable HTTPS/TLS (currently HTTP for local dev)
- ⚠️ Configure production-grade database (currently H2 file-based)
- ⚠️ Set up load balancing and redundancy
- ⚠️ Enable rate limiting at API gateway level
- ⚠️ Configure SIEM integrations with production credentials
- ⚠️ Set up log aggregation and retention policies
- ⚠️ Enable audit logging for compliance
- ⚠️ Configure backup and disaster recovery

---

## 📝 License & Purpose

Built as a **portfolio project** to demonstrate:
- ✅ Full stack security implementation
- ✅ Enterprise SIEM integration patterns
- ✅ Automated security testing methodologies
- ✅ Incident response automation
- ✅ OWASP Top 10 2021 comprehensive coverage
- ✅ Production-ready architecture with Spring Boot 3.5.0

**Not intended for production use** without additional security hardening, infrastructure setup, and compliance review.

---

## 👤 Author

**Darsh Sunilkumar**  
GitHub: [@dsun-1](https://github.com/dsun-1)  
Repository: [secure-transaction-monitoring](https://github.com/dsun-1/secure-transaction-monitoring)

---

## 🙏 Acknowledgments

- Spring Security team for comprehensive security framework
- OWASP for security best practices and Top 10 documentation
- Selenium WebDriver for browser automation capabilities
- TestNG for flexible test framework
- SpotBugs and FindSecBugs for static security analysis
- Elasticsearch and Splunk for SIEM platform inspiration

---

*Last Updated: November 10, 2025*  
*Version: 2.0 - Enterprise SIEM Edition*  
*OWASP Top 10 2021 Coverage: 10/10 (100%)* ✅
