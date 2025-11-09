# Interview Demo Guide

## Quick Demo (5 minutes)

### Setup (30 seconds)
```bash
# Terminal 1: Start the app
cd ecommerce-app
mvn spring-boot:run

# Wait for "Started EcommerceApplication" message
# Open browser: http://localhost:8080
```

### Demo Flow

**1. Show the Application (1 min)**
- "This is a mock e-commerce site I built for security testing"
- Add a laptop to cart ($1,299.99)
- Add headphones ($199.99)
- Show cart total: $1,499.98
- Click "Proceed to Checkout"

**2. Explain the Attack Surface (1 min)**
- "These are the vulnerable points I'm testing:"
  - Payment form (can users tamper with amounts?)
  - Session handling (can sessions be hijacked?)
  - Promo codes (can they be reused/stacked?)
  - Login flow (can accounts be brute-forced?)

**3. Run a Security Test (2 min)**
```bash
# Terminal 2: Run amount tampering test
cd security-tests
mvn test -Dtest=AmountTamperingTest

# Explain what's happening:
# "This test uses JavaScript injection to modify the payment amount
# in the DOM from $1,499.98 to $1.00, then submits it.
# The server should reject it, and we log the attempt."
```

**4. Show Detection & Response (1 min)**
```bash
# Check the security logs
cd scripts/python
python security_analyzer.py

# Show output:
# "The analyzer detected a payment tampering pattern and
# generated an incident report with severity, timestamp,
# and recommended actions."
```

**Optional: Show JIRA ticket that would be auto-created**

---

## Detailed Demo (15 minutes)

### Part 1: Architecture Overview (3 min)
"Let me walk you through how this works end-to-end..."

```
User Action → Security Test → Event Logger → SQL Database
                                                    ↓
JIRA Ticket ← Incident Report ← Python Analyzer ← SQL Query
```

### Part 2: Test Suite Overview (4 min)

**Show test structure:**
```bash
tree security-tests/src/test/java/com/security/tests
```

**Explain test categories:**
- Auth tests (5): Brute force, session hijacking, credential stuffing
- Payment tests (4): Amount tampering, negative values, invalid cards
- Business logic (4): Coupon abuse, cart manipulation, inventory bypass
- Injection tests (4): SQL injection, XSS, CSRF
- API tests (3): Rate limiting, authentication, data exposure

**Run multiple tests:**
```bash
mvn test -Dtest=BruteForceTest,SessionHijackingTest
```

### Part 3: Logging & Detection (4 min)

**Show database schema:**
"I created 3 tables to track different event types:"
- `security_events` - General security incidents
- `authentication_attempts` - Login tracking
- `transaction_anomalies` - Payment issues

**Show SecurityEventLogger.java:**
```java
public void logTransactionAnomaly(String transactionId, String username,
    String anomalyType, double originalAmount, double modifiedAmount) {
    // Logs to database with timestamp, session ID, IP address
}
```

**Run Python analyzer:**
```bash
python security_analyzer.py

# Show the 5 detection algorithms:
# 1. Brute force (5+ failures in 30 min)
# 2. Account enumeration (multiple username attempts)
# 3. Privilege escalation (unauthorized access patterns)
# 4. Transaction anomalies (amount mismatches)
# 5. Suspicious timing (2-5 AM activity)
```

### Part 4: CI/CD & Automation (2 min)

**Show GitHub Actions workflow:**
"Every night at 2 AM, this pipeline runs:"
1. Build & compile (with OWASP dependency check)
2. Run all 20+ security tests
3. Analyze logs with Python
4. Create JIRA tickets for high-severity findings
5. Send email notifications
6. Comment on PRs with security issues

**Show workflow file:**
```yaml
.github/workflows/security-tests.yml
```

### Part 5: Incident Response (2 min)

**Show playbook:**
"When an incident is detected, here's the workflow:"

1. **Detection** - Automated monitoring catches anomaly
2. **Triage** - Python script determines severity
3. **Ticket Creation** - JIRA ticket with full context
4. **Investigation** - SQL queries and PowerShell commands
5. **Containment** - Recommended actions
6. **Documentation** - Post-incident review

**Show actual incident report:**
```bash
cat docs/INCIDENT_RESPONSE_PLAYBOOK.md
```

---

## Common Interview Questions & Answers

**Q: How would this scale to production?**
A: "Right now it's using H2 (embedded database) which is fine for demos but you'd need:
- PostgreSQL or MySQL for the security logs
- Redis for session management
- Kafka for real-time event streaming
- ELK stack for log aggregation
The Python analyzer would become a microservice that processes events in real-time instead of batch."

**Q: What if you get false positives?**
A: "Good question. Right now I use simple thresholds (5 failures = brute force), but I'd add:
- Baseline learning (what's normal for each user/time/location)
- Confidence scores (not just binary true/false)
- Feedback loop so security team can mark false positives
- Machine learning for pattern recognition once you have enough training data"

**Q: How do you handle rate limiting?**
A: "The tests themselves have delays built in. For the actual app, you'd add:
- Spring Security's rate limiting
- Redis-based token bucket
- IP-based throttling
- CAPTCHA after X failures
I have a test for this (RateLimitingTest) but the app doesn't implement it yet - that's one of the known issues."

**Q: What about PII/sensitive data?**
A: "Everything in the logs is sanitized:
- Card numbers are masked (only last 4 digits)
- Passwords are never logged
- Email addresses are hashed in some tables
- The H2 database is local-only, not exposed
In production you'd add field-level encryption and comply with PCI-DSS."

**Q: How long did this take?**
A: "About 3-4 weeks working part-time:
- Week 1: Built the e-commerce app and basic test harness
- Week 2: Added security tests and logging infrastructure
- Week 3: Python analyzer and PowerShell monitoring
- Week 4: GitHub Actions, JIRA integration, documentation
The hardest part was getting Selenium tests to be reliable."

**Q: What would you do differently?**
A: "Three things:
1. Start with Docker from day 1 - would make deployment easier
2. Use TestContainers for isolated test databases
3. Add a real-time dashboard instead of just batch reports
Also, I'd write more of the injection tests - right now about half are stubs."

---

## Live Demo Script

**Opening:**
"Let me show you a security testing project I built. It's an end-to-end monitoring system for e-commerce transactions - from detecting attacks to creating incident tickets."

**[Show browser - home page]**
"Here's a basic e-commerce site with a checkout flow. Pretty standard stuff - cart, payment form, confirmation."

**[Add items to cart]**
"Let's say I'm buying a laptop and headphones - total is about $1,500."

**[Go to checkout]**
"Now, from a security perspective, this is interesting because users control all this data - shipping info, payment details, even the total amount that gets submitted."

**[Open terminal]**
"So I built automated tests that simulate actual attacks. Let me run the amount tampering test..."

**[Run test]**
"This test uses JavaScript injection to modify the DOM - it changes the price from $1,500 to $1 before submitting. A real attacker might do this with browser dev tools or a proxy like Burp Suite."

**[Wait for test to complete]**
"The test passed, meaning the server correctly rejected the tampering. But more importantly, the attempt was logged to the database."

**[Show Python analyzer]**
"Now here's where it gets interesting. This Python script reads the logs and looks for patterns - in this case, a transaction where the submitted amount doesn't match the cart total."

**[Run analyzer]**
"It detected the anomaly, calculated a severity score, and generated an incident report with recommendations. In a real environment, this would automatically create a JIRA ticket for the security team."

**[Show JIRA integration]**
"The ticket includes everything they need: timestamp, user session, IP address, what was attempted, and specific remediation steps."

**[Show GitHub Actions]**
"And this entire workflow runs automatically every night via GitHub Actions - tests run, logs are analyzed, tickets are created. No manual intervention needed."

**Closing:**
"So that's the project - it's not just testing, it's the full security operations lifecycle. Happy to dive deeper into any part of it."

---

## Key Points to Emphasize

✅ **End-to-end workflow** - Not just finding bugs, but detection → analysis → response

✅ **Real attack simulation** - Using Selenium to mimic actual attacker behavior

✅ **Pattern detection** - Goes beyond simple alerts to identify meaningful threats

✅ **Automation** - CI/CD pipeline runs everything automatically

✅ **Production-ready thinking** - Built with scalability in mind (even if not there yet)

✅ **Security best practices** - Based on OWASP Top 10 and industry standards

✅ **Practical application** - Python analyzer could run on real logs tomorrow
