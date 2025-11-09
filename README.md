# Secure Transaction Monitoring

Security testing project for e-commerce payment flows. Built this to learn more about application security testing and incident response workflows.

## What This Does

Testing harness for a mock checkout system that looks for common security issues - things like payment tampering, session problems, and authentication bypasses. When it finds something suspicious, it logs it to a database and can generate tickets automatically.

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

- Java 21 (upgraded from 17)
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

## Future Improvements

- Add more test coverage for API endpoints
- Containerize the whole thing with Docker
- Implement actual ML-based anomaly detection instead of just threshold rules
- Better reporting dashboard
- Add performance/load testing alongside security tests
