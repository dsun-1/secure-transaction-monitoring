# Secure E-Commerce Transaction Monitor

Security demo app that shows how web attacks are detected, logged, and turned into incidents.

## What it does

- Simulates attacks with Selenium/TestNG (DAST)
- Detects SQLi/XSS and auth abuse inside the Spring app
- Stores structured security events in H2
- Python analyzer groups events into incidents
- Optional JIRA ticket creation (dry-run supported)

## Quick start (demo mode)

### Prereqs

- Java 21
- Maven 3.8+
- Python 3.9+
- Chrome (or Firefox)

### Option A: one-command demo

```powershell
.\demo-interview.ps1
```

### Option B: manual steps

```bash
cd ecommerce-app
mvn clean package -DskipTests

# run the app
mvn spring-boot:run -Dspring-boot.run.profiles=demo
# or
java -Dspring.profiles.active=demo -jar target/ecommerce-app-1.0.0.jar
```

```bash
# in another terminal
cd security-tests
mvn test -Dheadless=true -Dbrowser=chrome -DbaseUrl=http://localhost:8080
```

```bash
# analyze events
python scripts/python/security_analyzer_h2.py
```

```bash
# optional JIRA tickets (dry-run if no creds)
python scripts/python/jira_ticket_generator.py
```

## Demo accounts (demo profile only)

| Username | Password | Role |
|---|---|---|
| testuser | password123 | USER |
| admin | admin123 | ADMIN |
| paymentuser | Paym3nt@123 | USER |

## Notes

- Demo profile seeds users and enables the H2 console.
- Security events are stored in `../data/security-events`.

## Repo map

- `ecommerce-app`: Spring Boot app with runtime detection and logging
- `security-tests`: Selenium/TestNG DAST suite
- `scripts/python`: SIEM analyzer + JIRA integration

## More details

See `DETAILS.md` for a slightly deeper overview (still short).
