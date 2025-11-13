# Secure Transaction Monitoring

A small demo platform for testing security monitoring, SIEM integrations, and alerting workflows. It includes a Spring Boot mock e-commerce app, security-focused test suites, and scripts to generate JIRA tickets or send alerts for detected incidents.

This README gives a quick way to build, run, and test the project locally and explains the main configuration points (JIRA, email, Slack, PagerDuty, and SIEM integrations).

## Contents

- `ecommerce-app/` — Spring Boot application (Thymeleaf UI, H2 DB).
- `security-tests/` — TestNG security tests targeting the application.
- `scripts/` — Helper scripts (Python & PowerShell) for alerts, JIRA ticket creation, and monitoring.
- `.github/workflows/` — CI workflows forgi running tests and creating JIRA tickets.

## Prerequisites
 
- Java 21 (the project is set up for Java 21 / Spring Boot 3.x)
- Maven 3.8+
- (Optional) Python 3.9+ to run Python scripts in `scripts/python`

## Build

From the repository root:

```powershell
mvn -T 1C clean package -DskipTests
```

Or build and run the ecommerce module only:

```powershell
cd ecommerce-app
mvn spring-boot:run
```

The app listens on port 8080 by default.

## Run (development)

1. Configure application properties (see below).
2. Run the app from your IDE or with:

```powershell
cd ecommerce-app
mvn spring-boot:run
```

Visit http://localhost:8080.

## Tests

Run the security tests module (TestNG):

```powershell
mvn -pl security-tests test
```

CI workflows in `.github/workflows/security-tests.yml` will also run these tests in CI.

## Configuration & Secrets

Main configuration is in `ecommerce-app/src/main/resources/application.properties`.
Sensitive values should not be stored in version control. Instead use environment variables or your CI secrets.

Important settings used by the project and CI workflows:

- `JIRA_URL` — JIRA base URL
- `JIRA_USERNAME` — JIRA account email used for API requests (also used as sender for email alerts)
- `JIRA_API_TOKEN` — API token for the JIRA user
- `alert.email.recipients` — Comma-separated list of recipients for security alert emails
- `alert.email.from` — Sender address; CI/workflows set this from `${JIRA_USERNAME}` by default
- `alert.slack.webhook` — Slack incoming webhook URL (if enabling Slack alerts)
- `alert.pagerduty.token` — PagerDuty API token (if enabling PagerDuty)

In local development you can set these in your shell or in your IDE run configuration. Example (PowerShell):

```powershell
$env:JIRA_URL = 'https://yourcompany.atlassian.net'
$env:JIRA_USERNAME = 'alerts@example.com'
$env:JIRA_API_TOKEN = 'REDACTED'
```

## Alerting & SIEM

- The `AlertManagerService` handles Slack, Email, and PagerDuty alerts. Email sending uses Spring Boot Mail. The sender address is read from `alert.email.from` and in CI is set from the `JIRA_USERNAME` secret.
- `SiemIntegrationService` will create JIRA tickets for SIEM events when enabled.
- Slack and PagerDuty features are scaffolded with TODOs — see `AlertManagerService.java` if you want to enable or complete them.

## Development notes

- Authentication is handled by Spring Security. Custom event handlers log authentication success/failure using `SecurityEventService`.
- `UserService` implements `UserDetailsService` to integrate with Spring Security.
- The H2 console can be enabled (`spring.h2.console.enabled=true`) for debugging (do not enable in production).

## How to contribute

1. Fork the repo and create a topic branch.
2. Make changes, run the tests locally.
3. Open a pull request with a description of the changes.

## Next steps / TODOs

- Implement Slack and PagerDuty integrations in `AlertManagerService` (currently TODO).
- Add more concrete integration tests that exercise the SIEM → JIRA flow end-to-end.

## License

This repository uses the project license in the repo (if present). If none is present, treat this code as internal/demo.

-