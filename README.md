# Secure Transaction Monitoring

This is a small demo platform for security monitoring and incident response. It has a Spring Boot mock e-commerce app, a security test suite that simulates attacks, and Python scripts that analyze events and generate incident reports.

If you want the quick version: run the app, run the tests, then run the SIEM analyzer.

## What this project shows

- End-to-end flow: attack simulation -> event logging -> detection -> report -> ticket creation.
- A simple SIEM-style pipeline built on top of an H2 event store.
- Automated security checks that map to OWASP Top 10 categories.

## Repo layout

- `ecommerce-app/` - Spring Boot app (Thymeleaf UI, H2 DB).
- `security-tests/` - TestNG + Selenium security tests.
- `scripts/` - Python/PowerShell scripts for analysis and JIRA ticket creation.
- `.github/workflows/` - CI workflows.

## Prerequisites

- Java 21
- Maven 3.8+
- (Optional) Python 3.9+ for `scripts/python`

## Build

From the repo root:

```powershell
mvn -T 1C clean package -DskipTests
```

Or just run the app:

```powershell
cd ecommerce-app
mvn spring-boot:run
```

The app runs on http://localhost:8080.

## Run (development)

1. Make sure `ecommerce-app/src/main/resources/application.properties` is set the way you want.
2. Start the app:

```powershell
cd ecommerce-app
mvn spring-boot:run
```

## Tests

Run the security test suite:

```powershell
mvn -pl security-tests test
```

CI uses `.github/workflows/security-tests.yml` to run the same tests headless.

## Configuration and secrets

Config lives in `ecommerce-app/src/main/resources/application.properties`.
For secrets, use env vars or CI secrets.

Common env vars:

- `JIRA_URL`
- `JIRA_USERNAME`
- `JIRA_API_TOKEN`
- `alert.email.recipients`
- `alert.email.from`

Example (PowerShell):

```powershell
$env:JIRA_URL = 'https://yourcompany.atlassian.net'
$env:JIRA_USERNAME = 'alerts@example.com'
$env:JIRA_API_TOKEN = 'REDACTED'
```

## Alerting and SIEM

- `scripts/python/security_analyzer_h2.py` reads the H2 event store and generates a JSON incident report.
- `scripts/python/jira_ticket_generator.py` can turn those incidents into JIRA tickets (dry run without creds).

## Notes

- Auth is handled by Spring Security.
- The H2 console can be enabled (`spring.h2.console.enabled=true`) for debugging, but do not use it in production.

## Next steps

- Add a fully end-to-end SIEM -> JIRA integration test.
