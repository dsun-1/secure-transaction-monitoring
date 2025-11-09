# Secure Transaction Monitoring

Security testing for e-commerce payment flows. Simulates attacks, logs events, detects patterns, and creates incident tickets.

## How It Works

```
Attack Simulation → Event Logging → Pattern Detection → Incident Report
    (Selenium)         (SQL DB)         (Python)          (JIRA)
```

1. **Selenium tests** simulate attacks (payment tampering, brute force, session hijacking)
2. **Security events** get logged to H2 database (authentication attempts, transaction anomalies)
3. **Python script** analyzes logs for patterns (5+ failed logins, price mismatches, suspicious timing)
4. **JIRA tickets** are auto-generated with incident details and recommended actions
5. **GitHub Actions** runs everything nightly

## Running It

```bash
# Start the app
cd ecommerce-app
mvn spring-boot:run

# Run tests (in another terminal)
cd security-tests
mvn test

# Analyze logs
cd scripts/python
python security_analyzer.py
```

Open http://localhost:8080 to see the e-commerce site.

## What's Included

- 20+ security test scenarios (auth, payment, business logic, injection, API)
- SQL logging (3 tables: security_events, authentication_attempts, transaction_anomalies)
- Python threat detection (5 algorithms: brute force, account enumeration, privilege escalation, transaction anomalies, suspicious timing)
- PowerShell system monitoring (Windows events, processes, failed logins)
- GitHub Actions CI/CD pipeline
- JIRA integration for ticket creation
- Incident response playbook

**Tech:** Java 21, Spring Boot, Selenium, TestNG, Python, PowerShell, Maven, H2, GitHub Actions
