# Secure E-Commerce Transaction Monitor

**Secure Transaction Monitoring** is a security engineering demo platform designed to simulate, detect, and respond to cyber threats in real-time. It features a vulnerable Spring Boot MVC application, an automated attack simulation suite, and a custom SIEM analyzer.

## Project Overview

This project demonstrates a complete **Attack → Detect → Respond** workflow:
1.  **Attack:** Automated Selenium tests simulate OWASP Top 10 threats (Brute Force, Session Hijacking, SQL Injection).
2.  **Detect:** The application logs security events to a structured H2 database.
3.  **Analyze:** A Python-based SIEM analyzer queries the database to correlate events and identify anomalies.
4.  **Respond:** Confirmed incidents are formatted for automated ticketing (JIRA integration).

## Tech Stack

*   **Core:** Java 21, Spring Boot 3 (MVC), Spring Security
*   **Data:** H2 Database (SQL), Jakarta Validation
*   **Frontend:** Thymeleaf (Server-Side Rendering)
*   **Testing:** Selenium WebDriver, TestNG
*   **Ops:** Python (JayDeBeApi), GitHub Actions (Headless CI)

## Repository Structure

*   `ecommerce-app/` - The target application. A monolithic Spring Boot app using Thymeleaf for UI and H2 for data persistence. Implements RBAC and input validation.
*   `security-tests/` - The attack suite. Uses Selenium and TestNG to perform black-box security testing against the running app.
*   `scripts/python/` - The detection engine. `security_analyzer_h2.py` connects to the H2 database via JDBC to run detection logic.
*   `.github/workflows/` - CI pipeline configuration for headless testing.

## Quick Start (Demo Mode)

**Prerequisites:** Java 21, Maven 3.8+, Python 3.9+

1.  **Start the Application:**
    ```powershell
    mvn -f ecommerce-app/pom.xml spring-boot:run
    ```
    *App runs on http://localhost:8080*

2.  **Run Attack Simulation (New Terminal):**
    ```powershell
    mvn -f security-tests/pom.xml test
    ```

3.  **Run SIEM Analysis:**
    ```powershell
    python scripts/python/security_analyzer_h2.py
    ```

## Key Features

*   **Role-Based Access Control (RBAC):** Spring Security configuration ensuring strict separation between `USER` and `ADMIN` roles.
*   **Rate Limiting:** Custom filter implementing a sliding window algorithm to block high-frequency requests (DoS protection).
*   **Session Management:** Secure session handling that ties cart data to `JSESSIONID`, serving as the target for session hijacking simulations.
*   **Defensive Programming:** Extensive use of `Jakarta Validation` (`@NotBlank`, `@Pattern`) to enforce data integrity at the model level.
*   **Security Event Logging:** Custom event listeners capture authentication failures and suspicious transactions.
*   **CI/CD Integration:** Tests are designed to run headlessly in GitHub Actions to enforce secure SDLC practices.

## Configuration

Configuration is managed in `ecommerce-app/src/main/resources/application.properties`.
The H2 database is stored in `ecommerce-app/data/security-events`.

## License
MIT

