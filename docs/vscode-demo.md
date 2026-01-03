# VS Code demo workflow

This project can be demonstrated end-to-end from VS Code using the integrated terminal, Tasks, and a database client.

## One-time setup

1. Open the repository root in VS Code.
2. Install recommended extensions when prompted (see `.vscode/extensions.json`).
3. Ensure Java 21, Maven, and Python 3.9+ are available on PATH.

## Run the end-to-end flow

You can run everything from the VS Code command palette:

1. Press Ctrl+Shift+P and select "Tasks: Run Task".
2. Run tasks in this order:
   - "App: Run Spring Boot"
   - "Tests: Run Security Suite"
   - "SIEM: Analyze H2 Events"
   - "SIEM: Create JIRA Tickets"

These tasks use integrated terminals so you can show the full attack -> detection -> analysis -> response sequence in one place.

## Database inspection (H2)

Option A: H2 console (built-in)
- Start the app.
- Open http://localhost:8080/h2-console.
- JDBC URL: `jdbc:h2:file:./data/security-events`
- Username: `sa`
- Password: (leave blank)

Option B: VS Code database client
- Install SQLTools and the H2 driver.
- Create a new connection pointing at the same JDBC URL.

## Scripts (integrated terminal)

From the VS Code terminal you can run:

```powershell
cd scripts/python
python security_analyzer_h2.py
python jira_ticket_generator.py siem_incident_report.json
```