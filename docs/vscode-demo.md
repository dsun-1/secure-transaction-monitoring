# VS Code demo workflow

This project can be demonstrated end-to-end from VS Code using the integrated terminal and a database client.

## One-time setup

1. Open the repository root in VS Code.
2. Ensure Java 21, Maven, and Python 3.9+ are available on PATH.
3. (Optional) Install a database client extension such as SQLTools with the H2 driver.

## Run the end-to-end flow (manual terminals)

Open multiple integrated terminals and run these steps in order:

1. Start the app:
   - `cd ecommerce-app`
   - `mvn spring-boot:run`
2. Run the security tests:
   - `mvn -pl security-tests test`
3. Analyze security events:
   - `cd scripts/python`
   - `python security_analyzer_h2.py`
4. Generate JIRA tickets (optional):
   - `python jira_ticket_generator.py siem_incident_report.json`

## Database inspection (H2)

Option A: H2 console (built-in)
- Start the app.
- Open `http://localhost:8080/h2-console`.
- JDBC URL: `jdbc:h2:file:./data/security-events`
- Username: `sa`
- Password: (leave blank)

Option B: VS Code database client
- Create a connection with the same JDBC URL.
