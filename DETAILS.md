# Secure E-Commerce Transaction Monitor Details

A short, human-readable overview of the stack and security controls.

## Tech stack (high level)

- Java 21, Spring Boot 3.x, Spring Security 6
- Spring MVC + Thymeleaf
- H2 database (file-based)
- Maven build
- Selenium + TestNG for DAST
- Python for SIEM analysis and JIRA integration

## Security controls (app side)

- Login + role-based access (USER / ADMIN)
- CSRF protection and secure sessions
- Sliding-window rate limiting
- Input pattern checks for SQLi/XSS
- Security headers (CSP, HSTS, etc.)
- Structured event logging to H2

## DAST suite (security-tests)

- Browser-driven tests that attack the app like a real client
- Focused on injection and auth-abuse scenarios
- Runs headless by default; browser can be switched by flag

## SIEM + incident flow (scripts/python)

- Reads security events from H2
- Correlates events into incidents
- Optional JIRA ticket generation (supports dry-run)

## Key config + env vars

- App profiles: `default` and `demo`
- Demo profile seeds users and enables the H2 console
- JIRA env vars (optional):
  - `JIRA_URL`, `JIRA_USERNAME`, `JIRA_API_TOKEN`, `JIRA_PROJECT_KEY`

## CI

- GitHub Actions workflow runs the DAST suite in headless mode
- Artifacts include test reports and analysis output
