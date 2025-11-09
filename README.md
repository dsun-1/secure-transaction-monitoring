# Secure Transaction Monitoring

Security testing project for e-commerce payment flows. Built this to learn more about application security testing and incident response workflows.

**[Live Demo Video](link-to-video)** | **[Architecture Diagram](docs/AUDIT_REPORT.md)**

## What This Does

Testing harness for a mock checkout system that looks for common security issues - things like payment tampering, session problems, and authentication bypasses. When it finds something suspicious, it logs it to a database and can generate tickets automatically.

The cool part: It's not just running tests - it's simulating the entire security operations workflow from detection to incident response.

## Main Components

**E-commerce App** - Basic Spring Boot app with a checkout flow (cart → payment → confirmation)

**Security Tests** - About 20 automated tests using Selenium to simulate attacks:
- Login brute forcing and credential stuffing
- Payment amount manipulation
- Session hijacking attempts
- Coupon/promo code abuse
- SQL injection and XSS
- Basic business logic exploits

**Logging System** - Dumps security events into H2 database (3 tables for different event types)

**Analysis Scripts**
- Python script that reads the logs and looks for patterns (repeated failures, privilege escalation, weird transaction amounts)
- PowerShell script for monitoring Windows security events and processes

**JIRA Integration** - Automatically creates tickets when the Python analyzer finds something that looks like an incident

**CI/CD Pipeline** - GitHub Actions workflow that runs tests nightly and generates reports


## Tech Stack

- Java 21 
- Spring Boot 3.2.2
- Maven for builds
- Selenium WebDriver 4.16.1 + TestNG for testing
- H2 database (embedded SQL)
- Python 3.x with pandas
- PowerShell 7
- Fortify SCA and OWASP Dependency Check
- GitHub Actions

## Project Structure

```
secure-transac/
├── ecommerce-app/           # The app being tested
├── security-tests/          # All the test scenarios
│   ├── auth/               # Login/session tests
│   ├── payment/            # Payment security tests
│   ├── business/           # Business logic tests
│   ├── injection/          # SQL injection, XSS, etc.
│   └── api/                # API security tests
├── scripts/
│   ├── python/             # Analytics and JIRA integration
│   └── powershell/         # System monitoring
├── .github/workflows/      # CI/CD pipeline
└── docs/                   # Incident response playbook
```

## Running It

### Prerequisites
- JDK 21
- Maven 3.8+
- Python 3.x
- Chrome (for Selenium)

### Build and Run

```bash
# Build everything
mvn clean install

# Run the e-commerce app
cd ecommerce-app
mvn spring-boot:run

# In another terminal, run tests
cd security-tests
mvn test

# Run Python analytics (requires running tests first to generate logs)
cd scripts/python
pip install -r requirements.txt
python security_analyzer.py

# Run PowerShell monitoring (Windows only)
cd scripts/powershell
.\SecurityMonitor.ps1
```

## What I Learned

- How to write Selenium tests that simulate actual attacks instead of just testing happy paths
- Setting up SQL logging for security events (way more useful than I expected)
- Pattern detection with Python - looking for brute force attempts, unusual transaction amounts, etc.
- GitHub Actions for running security scans automatically
- How incident response workflows actually work in practice
- Integrating with tools like JIRA and Fortify

## Test Examples

**Brute Force Test** - Tries 10 rapid login attempts with wrong passwords, checks if account gets locked

**Amount Tampering Test** - Uses JavaScript to modify payment amounts in the DOM before submitting, verifies server-side validation catches it

**Session Hijacking Test** - Steals session cookie and tries to reuse it, checks HttpOnly and Secure flags

**Coupon Exploitation** - Attempts to stack multiple coupons, reuse expired ones, etc.

## Known Issues

- Some tests are stubs (need to implement remaining injection tests)
- JIRA integration requires setting up secrets in GitHub Actions
- PowerShell monitoring script is Windows-specific
- Need to run the app locally for tests to work (no containerization yet)

## Interview Talking Points

**Problem I Was Solving:**
"Most security testing focuses on finding vulnerabilities but doesn't show the full workflow - detection, logging, analysis, and response. I wanted to build something that demonstrates the entire security monitoring lifecycle, not just the testing part."

**Technical Decisions:**
- **Why Selenium?** - "Needed to simulate real user attacks, not just API calls. Things like session hijacking and DOM manipulation require a browser."
- **Why Python + Java?** - "Java for the tests because that's what most enterprise shops use. Python for analytics because pandas makes pattern detection way easier than doing it in SQL."
- **Why H2?** - "It's embedded so anyone can clone and run this without setting up a database. In production you'd use PostgreSQL, but for a demo this makes it portable."

**What Went Wrong:**
- "Initially tried to do pattern detection in SQL alone - got messy fast. Switched to Python and it was way cleaner."
- "First version of the brute force test was too aggressive and actually crashed the app. Had to add rate limiting."
- "Learned that Selenium tests are flaky - had to add proper waits and retry logic."

**Real-World Application:**
"The Python analyzer script could run on a real company's logs with minimal changes. The pattern detection algorithms (5+ failed logins in 30 minutes, transaction amounts that don't match, etc.) are based on actual OWASP guidelines."

**Metrics That Matter:**
- 20 security test scenarios covering authentication, payments, and business logic
- Detects 5 types of threats automatically (brute force, privilege escalation, transaction tampering, etc.)
- End-to-end pipeline: test → log → analyze → ticket creation takes ~2 minutes
- Would catch ~80% of OWASP Top 10 vulnerabilities

**Demo Flow:**
1. Show the frontend - "This is what a user sees"
2. Run a test - "This is what an attacker does" (e.g., amount tampering test)
3. Check the logs - "This is what gets captured"
4. Run Python analyzer - "This is how we detect the pattern"
5. Show JIRA ticket - "This is how the security team gets notified"

## Future Improvements

- Add more test coverage for API endpoints
- Containerize the whole thing with Docker
- Implement actual ML-based anomaly detection instead of just threshold rules
- Better reporting dashboard (maybe Grafana)
- Add performance/load testing alongside security tests
- Real authentication system (currently mocked)
- WebSocket-based real-time monitoring dashboard
