# Secure E-Commerce Transaction Monitor

Security engineering demo for internship interview showcasing runtime security monitoring, SIEM integration, and automated incident response on a Spring Boot e-commerce application.

## Project Overview

This project demonstrates a complete **Attack -> Detect -> Analyze -> Respond** workflow using modern security engineering practices:

1. **Attack Simulation**: Automated TestNG test suite with Selenium WebDriver simulates OWASP Top 10 threats
2. **Runtime Detection**: Spring Boot application detects attacks in real-time and logs structured security events to H2 database
3. **SIEM Analysis**: Python analyzer correlates events, identifies attack patterns, and generates incident reports
4. **Incident Response**: JIRA integration creates tickets for security teams (with dry-run fallback)

## Complete Technology Stack

### Backend Framework & Runtime

- **Java 21**: LTS runtime with modern language features
- **Spring Boot 3.5.0**: Application framework with auto-configuration
- **Spring MVC**: Web layer with RESTful controllers
- **Spring Security 6.x**: Authentication, authorization, and security filters
- **Spring Data JPA**: Data access with Hibernate ORM
- **Embedded Tomcat**: Servlet container (managed by Spring Boot)

### Data Layer

- **H2 Database 2.2.224**: File-based SQL database (`../data/security-events`)
- **Jakarta Persistence API (JPA)**: ORM specification
- **Hibernate**: JPA implementation
- **HikariCP**: High-performance JDBC connection pool
- **Jakarta Validation**: Bean validation (JSR-380)

### Security Implementation

- **BCrypt Password Hashing**: Using Spring Security's `PasswordEncoder`
- **CSRF Protection**: Token-based with `CookieCsrfTokenRepository`
- **Session Management**: Concurrent session control, fixation protection
- **Rate Limiting**: Custom in-memory sliding window filter (50 req/5s)
- **Security Headers**: X-Content-Type-Options (nosniff), X-Frame-Options (sameOrigin)
- **Custom Authentication**: `ApiAuthEntryPoint` for 401 responses
- **Access Denied Handler**: `SecurityAccessDeniedHandler` for 403 responses
- **Pattern-based Detection**: SQLi/XSS detection in ProductController and SecurityConfig

### Frontend & Templates

- **Thymeleaf**: Server-side HTML template engine
- **Bootstrap 5**: CSS framework for responsive UI
- **HTML5/CSS3**: Modern web standards
- **JavaScript**: Client-side interactions

### Testing & Automation

- **Selenium WebDriver 4.27.0**: Browser automation for attack simulation
- **TestNG 7.9.0**: Testing framework with annotations and parallel execution
- **WebDriverManager**: Automatic browser driver management
- **RestAssured**: REST API testing for header validation
- **Chrome/Firefox Drivers**: Headless browser support

### SIEM & Analytics

- **Python 3.9+**: SIEM analyzer runtime
- **JayDeBeApi 1.2.3**: Python-to-JDBC bridge for H2 access
- **JPype1 1.4.0**: Java Virtual Machine integration for Python

### Incident Management

- **JIRA REST API**: Ticket creation for incidents
- **Python Requests**: HTTP client for JIRA integration
- **JSON**: Incident report format

### Build & Deployment

- **Maven 3.8+**: Multi-module build tool
- **Maven Surefire**: Test execution plugin
- **Maven Compiler Plugin**: Java 21 compilation
- **Spring Boot Maven Plugin**: JAR packaging with embedded server
- **PowerShell**: Demo orchestration script

### CI/CD & DevOps

- **GitHub Actions**: Automated testing workflows
- **YAML**: Workflow configuration
- **Git**: Version control

## Security Controls Implemented

### Authentication & Authorization

- **Role-Based Access Control (RBAC)**: `USER`, `ADMIN` roles with `@PreAuthorize` annotations
- **BCrypt Password Hashing**: Salted adaptive hashing (cost factor 10)
- **Form-Based Authentication**: Username/password login with Spring Security
- **Session-Based Auth**: HTTP sessions with secure cookie attributes
- **Concurrent Session Control**: Maximum 1 session per user
- **Session Fixation Protection**: New session ID on authentication

### Input Validation & Sanitization

- **Jakarta Validation**: `@NotBlank`, `@Size`, `@Min`, `@Max` constraints on entities
- **Pattern-Based Detection**: SQL injection keywords detection in login/search
- **XSS Pattern Detection**: Script tag and event handler detection
- **Parameterized Queries**: JPA `@Query` with named parameters, JDBC `PreparedStatement`
- **Thymeleaf Auto-Escaping**: HTML entity encoding by default

### CSRF Protection

- **Token Validation**: `CookieCsrfTokenRepository` with double-submit cookies
- **Form Integration**: Thymeleaf `th:action` auto-includes CSRF tokens
- **Stateless CSRF**: Cookie-based tokens (no server-side storage)

### Secure Headers

- **X-Content-Type-Options**: `nosniff` prevents MIME sniffing
- **X-Frame-Options**: `sameOrigin` prevents clickjacking
- **X-XSS-Protection**: Enabled for legacy browser support
- **Cache-Control**: `no-cache, no-store, must-revalidate` for sensitive pages

### Rate Limiting

- **Sliding Window Algorithm**: In-memory tracker per IP address
- **Threshold**: 50 requests per 5 seconds
- **Protected Endpoints**: `/products`, `/api/security/**`
- **Custom Filter**: `RateLimitingFilter` integrated in Spring Security chain
- **Bypass Detection**: IP spoofing detection (X-Forwarded-For), session rotation attacks, slowloris-style threshold evasion

### Security Event Logging

- **Structured Events**: Security events with type, severity, username, IP, timestamp
- **Event Types**: 36 event types including `SQL_INJECTION_ATTEMPT`, `XSS_ATTEMPT`, `BRUTE_FORCE_DETECTED`, `CSRF_VIOLATION`, `RATE_LIMIT_EXCEEDED`, `RACE_CONDITION_DETECTED`, `CRYPTOGRAPHIC_FAILURE`, `PRIVILEGE_ESCALATION_ATTEMPT`
- **Database Persistence**: H2 tables for `security_events`, `authentication_attempts`, `transaction_anomalies`
- **Indexed Queries**: Optimized for SIEM correlation

### Transactional Integrity

- **ACID Transactions**: `@Transactional` on service layer methods
- **Rollback on Exception**: Automatic rollback for runtime exceptions
- **Optimistic Locking**: JPA `@Version` for concurrent updates

## Attack Simulation Suite

**OWASP Top 10 2021 Coverage**: 8 out of 10 categories (80%)

### A01: Broken Access Control (90% Coverage)

- **Horizontal Access Control**: User accessing other users' data
- **Vertical Privilege Escalation**: USER role accessing ADMIN endpoints
- **IDOR (Insecure Direct Object Reference)**: Direct cart/order manipulation
- **Forced Browsing**: Unauthenticated access to protected resources
- **API Authentication**: Unauthorized API access attempts

### A02: Cryptographic Failures (60% Coverage)

- **TLS Enforcement**: HTTPS redirect validation, HSTS header verification
- **Secure Cookie Flags**: Session cookie security attribute validation
- **Sensitive Data Exposure**: localStorage/sessionStorage data leakage detection
- **HttpOnly Cookie Testing**: JavaScript cookie access prevention
- **Password Exposure in DOM**: Hardcoded credentials detection

### A03: Injection (90% Coverage)

- **SQL Injection**: Login bypass attempts, UNION-based queries, search parameter injection
- **XSS (Cross-Site Scripting)**: Reflected XSS in search, stored XSS attempts, script injection
- **CSRF**: Token bypass attempts, missing token validation
- **SSRF (Server-Side Request Forgery)**: file:// protocol access, localhost bypass, cloud metadata access, private IP ranges

### A04: Insecure Design (70% Coverage)

- **Rate Limit Bypass**: IP spoofing (X-Forwarded-For header manipulation), session rotation attacks, slowloris-style threshold evasion
- **Race Conditions**: Concurrent cart updates, duplicate item additions, double checkout vulnerabilities
- **Business Logic Flaws**: Amount tampering, cart manipulation, negative amounts, decimal precision attacks

### A05: Security Misconfiguration (75% Coverage)

- **Missing Security Headers**: X-Content-Type-Options, X-Frame-Options validation
- **Stack Trace Exposure**: Exception details in error responses
- **HTTP Method Leakage**: OPTIONS method information disclosure
- **Verbose Error Messages**: Debug information exposure
- **Directory Listing**: Resource enumeration attempts

### A07: Identification and Authentication Failures (90% Coverage)

- **Brute Force**: 50 rapid login attempts with different passwords
- **Account Enumeration**: Username discovery via timing attacks
- **Session Hijacking**: Cookie theft simulation
- **Session Fixation**: Pre-set session ID attacks
- **Credential Stuffing**: Distributed authentication attempts

### A10: Server-Side Request Forgery (70% Coverage)

- **Protocol Bypass**: file://, http://localhost attempts
- **Cloud Metadata Access**: AWS/Azure/GCP metadata endpoints (169.254.169.254)
- **Private IP Scanning**: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 ranges
- **Localhost Variants**: 127.0.0.1, [::1], 0.0.0.0 bypasses

**Not Covered (By Design)**:

- **A06: Vulnerable and Outdated Components**: Requires dependency scanning (SAST/SCA tools like OWASP Dependency-Check, Snyk)
- **A08: Software and Data Integrity Failures**: Requires CI/CD pipeline integration (signature verification, supply chain security)
- **A09: Security Logging and Monitoring Failures**: This project IS the monitoring solution

## SIEM Analysis Capabilities

### Pattern Detection

- **Brute Force Detection**: >5 failed logins within 5 minutes for same username
- **Distributed Brute Force**: >10 failed logins within 5 minutes across usernames
- **Account Enumeration**: >3 enumeration attempts within 2 minutes
- **Transaction Anomalies**: Price tampering, cart manipulation correlation

### Incident Severity Classification

- **CRITICAL**: Successful exploitation, data breach indicators
- **HIGH**: Active attack patterns (brute force, injection attempts)
- **MEDIUM**: Suspicious behavior (enumeration, reconnaissance)
- **LOW**: Policy violations, minor misconfigurations

### Correlation Logic

- **Time Window Analysis**: Event correlation within configurable time windows
- **Username Grouping**: Attack pattern tracking per user account
- **IP Address Tracking**: Source attribution for distributed attacks
- **Event Type Clustering**: Related event aggregation

## Repository Structure

```
secure-transac/
??? ecommerce-app/                    # Spring Boot Application
?   ??? src/main/java/com/security/ecommerce/
?   ?   ??? EcommerceApplication.java           # Main application entry point
?   ?   ??? config/                             # Security & infrastructure config
?   ?   ?   ??? SecurityConfig.java             # Spring Security configuration
?   ?   ?   ??? RateLimitingFilter.java         # Custom rate limiting filter
?   ?   ?   ??? ApiAuthEntryPoint.java          # 401 authentication entry point
?   ?   ?   ??? SecurityAccessDeniedHandler.java # 403 access denied handler
?   ?   ?   ??? DataInitializer.java            # Demo user seeding
?   ?   ?   ??? RequestInspectionFilter.java    # Request logging filter
?   ?   ??? controller/                         # MVC controllers
?   ?   ?   ??? ProductController.java          # Product listing with SQLi/XSS detection
?   ?   ?   ??? CheckoutController.java         # Payment flow controller
?   ?   ?   ??? AuthController.java             # Login/logout endpoints
?   ?   ?   ??? SecurityDashboardController.java # Admin security dashboard
?   ?   ??? model/                              # JPA entities
?   ?   ?   ??? User.java                       # User entity with roles
?   ?   ?   ??? Product.java                    # Product catalog entity
?   ?   ?   ??? CartItem.java                   # Shopping cart entity
?   ?   ?   ??? SecurityEvent.java              # Security event entity
?   ?   ??? repository/                         # Spring Data repositories
?   ?   ?   ??? UserRepository.java
?   ?   ?   ??? ProductRepository.java
?   ?   ?   ??? CartItemRepository.java
?   ?   ?   ??? SecurityEventRepository.java
?   ?   ??? service/                            # Business logic layer
?   ?       ??? UserService.java                # User management & authentication
?   ?       ??? ProductService.java             # Product operations
?   ?       ??? CartService.java                # Cart management
?   ?       ??? SecurityEventService.java       # Security event logging
?   ?       ??? CheckoutService.java            # Payment processing
?   ??? src/main/resources/
?   ?   ??? application.properties              # Production configuration
?   ?   ??? application-demo.properties         # Demo profile with test users
?   ?   ??? templates/                          # Thymeleaf HTML templates
?   ?       ??? login.html                      # Login form with CSRF
?   ?       ??? products.html                   # Product catalog
?   ?       ??? cart.html                       # Shopping cart
?   ?       ??? checkout.html                   # Payment form
?   ?       ??? confirmation.html               # Order confirmation
?   ??? pom.xml                                 # Maven dependencies & build config
?
??? security-tests/                   # Automated Attack Simulation Suite
?   ??? src/test/java/com/security/tests/
?   ?   ??? base/
?   ?   ?   ??? BaseTest.java                   # Selenium setup & event logger (headless default)
?   ?   ??? injection/                          # Injection attack tests (OWASP A03)
?   ?   ?   ??? SQLInjectionTest.java           # SQL injection attempts
?   ?   ?   ??? XSSTest.java                    # XSS attack simulation
?   ?   ?   ??? CSRFTest.java                   # CSRF token bypass attempts
?   ?   ?   ??? SSRFTest.java                   # SSRF protocol/IP bypass tests
?   ?   ??? auth/                               # Authentication attack tests (OWASP A01, A07)
?   ?   ?   ??? BruteForceTest.java             # Login brute force (50 attempts)
?   ?   ?   ??? SessionFixationTest.java        # Session fixation attacks
?   ?   ?   ??? SessionHijackingTest.java       # Session theft simulation
?   ?   ?   ??? PrivilegeEscalationTest.java    # Vertical privilege escalation (USER -> ADMIN)
?   ?   ?   ??? AccessControlTest.java          # Horizontal access control, IDOR, forced browsing
?   ?   ??? api/                                # API security tests (OWASP A04)
?   ?   ?   ??? APIAuthenticationTest.java      # Unauthorized API access
?   ?   ?   ??? RateLimitingTest.java           # Rate limit enforcement + bypass (IP spoofing, session rotation, slowloris)
?   ?   ??? business/                           # Business logic attack tests (OWASP A04)
?   ?   ?   ??? AmountTamperingTest.java        # Price manipulation attacks
?   ?   ?   ??? CartManipulationTest.java       # Cart tampering tests
?   ?   ?   ??? RaceConditionTest.java          # Concurrent cart/checkout race conditions
?   ?   ??? config/                             # Security configuration tests (OWASP A05)
?   ?   ?   ??? SecurityMisconfigurationTest.java # Headers, stack traces, OPTIONS method leakage
?   ?   ??? crypto/                             # Cryptographic tests (OWASP A02)
?   ?   ?   ??? TLSEnforcementTest.java         # HTTPS redirect, HSTS, Secure cookies
?   ?   ?   ??? DataExposureTest.java           # localStorage/sessionStorage/DOM exposure, HttpOnly cookies
?   ?   ??? utils/                              # Test utilities
?   ?       ??? SecurityEvent.java              # Event POJO for test logging
?   ?       ??? SecurityEventLogger.java        # Direct H2 event writer (36 event types)
?   ??? src/test/resources/
?   ?   ??? testng.xml                          # TestNG suite configuration (16 test classes)
?   ??? pom.xml                                 # Selenium & TestNG dependencies
?
??? scripts/python/                   # SIEM & Incident Response
?   ??? security_analyzer_h2.py                 # SIEM analyzer (pattern detection)
?   ??? jira_ticket_generator.py                # JIRA ticket creation (dry-run capable)
?   ??? requirements.txt                        # Python dependencies
?
??? .github/workflows/                # CI/CD Automation
?   ??? security-tests.yml                      # Automated security testing
?   ??? manual-jira-tickets.yml                 # Manual JIRA workflow trigger
?
??? data/                             # Runtime data (gitignored)
?   ??? security-events.mv.db                   # H2 database file
?
??? demo-interview.ps1                # One-command demo orchestration script
??? pom.xml                           # Parent POM for multi-module build
??? README.md                         # This file
```

## Quick Start (Demo Mode)

### Prerequisites

- **Java 21**: Download from [Adoptium](https://adoptium.net/) or Oracle
- **Maven 3.8+**: Build automation tool
- **Python 3.9+**: For SIEM analyzer and JIRA integration
- **Chrome Browser**: Required for Selenium WebDriver tests (Firefox also supported)
- **Git**: Version control (for cloning repository)

### Python Dependencies

```bash
pip install -r scripts/python/requirements.txt
# Installs: JayDeBeApi (1.2.3), JPype1 (1.4.0), requests
```

### Option A: One-Command Demo (Recommended)

```powershell
.\demo-interview.ps1
```

This script automatically:

1. Builds the Spring Boot JAR (`mvn clean package -DskipTests`)
2. Starts the application in a separate window with demo profile
3. Waits for application to be ready (health check on port 8080)
4. Runs the complete TestNG attack simulation suite (28 tests)
5. Analyzes security events with Python SIEM (`security_analyzer_h2.py`)
6. Generates JIRA incident tickets in dry-run mode (`jira_ticket_generator.py`)
7. Displays summary of attacks detected, incidents created, and severity breakdown

**Expected Results:**

- **Tests**: 47+ tests executed across 16 test classes
- **Security Events**: 80+ HIGH/MEDIUM severity events logged
- **SIEM Incidents**: 5-6 incidents detected (brute force, enumeration, transaction anomalies, race conditions)
- **OWASP Coverage**: 8 out of 10 categories (80% coverage: A01, A02, A03, A04, A05, A07, A10)
- **JIRA Tickets**: Generated in dry-run mode (or created if JIRA credentials configured)

### Option B: Manual Step-by-Step

#### 1. Build the Application

```bash
cd ecommerce-app
mvn clean package -DskipTests
```

#### 2. Start Application with Demo Profile

```bash
# Option A: Using Maven
mvn spring-boot:run -Dspring-boot.run.profiles=demo

# Option B: Using JAR
java -Dspring.profiles.active=demo -jar target/ecommerce-app-1.0.0.jar
```

Application starts on **http://localhost:8080** with:

- Demo users seeded (testuser, admin, paymentuser)
- H2 database at `../data/security-events`
- Security event logging enabled

#### 3. Run Attack Simulation Suite (New Terminal)

```bash
cd security-tests
mvn test -Dheadless=true -Dbrowser=chrome -DbaseUrl=http://localhost:8080
```

**Test Execution:**

- **Headless Mode**: Browsers run without GUI (`-Dheadless=true`)
- **Browser Selection**: Chrome or Firefox (`-Dbrowser=chrome`)
- **Parallel Execution**: 5 threads for faster execution
- **Duration**: ~3-5 minutes for complete suite

#### 4. Run SIEM Analysis

```bash
python scripts/python/security_analyzer_h2.py
```

**Output**: `siem_incident_report.json` with:

- Detected incidents with severity and timestamps
- Attack patterns (brute force, enumeration, injection attempts)
- Affected usernames and IP addresses
- Event counts and correlation details

#### 5. Generate JIRA Tickets (Optional)

```bash
# Dry-run mode (no JIRA credentials required)
python scripts/python/jira_ticket_generator.py

# Production mode (requires environment variables)
$env:JIRA_URL = "https://your-domain.atlassian.net"
$env:JIRA_USERNAME = "your-email@example.com"
$env:JIRA_API_TOKEN = "your-api-token"
$env:JIRA_PROJECT_KEY = "SEC"
python scripts/python/jira_ticket_generator.py
```

## Demo User Credentials

Test accounts seeded in **demo profile only** (`application-demo.properties`):

| Username | Password | Role | Purpose |
|----------|----------|------|---------|
| `testuser` | `password123` | USER | Standard user account for login/session tests |
| `admin` | `admin123` | ADMIN | Administrator for privileged operations testing |
| `paymentuser` | `Paym3nt@123` | USER | Transaction and payment flow testing |

**Security Note**: These credentials are intentionally weak for attack simulation. Production systems use strong password policies enforced via Jakarta Validation.

## Configuration Details

### Application Properties

**Production Config** (`application.properties`):

```properties
# Server Configuration
server.port=8080

# H2 Database (File-based)
spring.datasource.url=jdbc:h2:file:../data/security-events
spring.datasource.driver-class-name=org.h2.Driver
spring.jpa.hibernate.ddl-auto=update
spring.jpa.show-sql=false

# H2 Console (Disabled by default)
spring.h2.console.enabled=false

# Thymeleaf Template Engine
spring.thymeleaf.cache=true

# Logging
logging.level.root=INFO
logging.level.com.security.ecommerce=INFO
```

**Demo Profile** (`application-demo.properties`):

```properties
# Demo user seeding
demo.users.enabled=true

# H2 Console (Enabled for demo)
spring.h2.console.enabled=true
spring.h2.console.path=/h2-console

# Enhanced logging for demo
logging.level.com.security.ecommerce=DEBUG
logging.level.org.springframework.security=DEBUG

# Thymeleaf hot reload
spring.thymeleaf.cache=false
```

### Test Configuration

**TestNG Suite** (`testng.xml`):

- **Thread Count**: 5 (parallel test execution)
- **Verbose Level**: 1 (minimal output)
- **Test Classes**: 16 active test classes (13 functional security tests, 1 destructive test, 2 cryptographic tests)
- **Listener**: ExtentReports for HTML test reports
- **Headless Mode**: Enabled by default (no browser UI)

**System Properties**:

- `-Dheadless=true/false`: Browser display mode
- `-Dbrowser=chrome/firefox`: Browser selection
- `-DbaseUrl=http://localhost:8080`: Application URL

### Environment Variables

**JIRA Integration** (Optional):

```bash
JIRA_URL=https://your-domain.atlassian.net
JIRA_USERNAME=your-email@example.com
JIRA_API_TOKEN=your-api-token
JIRA_PROJECT_KEY=SEC
```

**Python/JDBC**:

- `JAVA_HOME`: Required for JPype1 to find JVM
- Path to H2 JDBC driver: Auto-detected from Maven repository

## API Endpoints

### Public Endpoints

- `GET /`: Home page redirect to login
- `GET /login`: Login form (CSRF protected)
- `POST /perform_login`: Login submission handler
- `POST /logout`: Logout handler

### Authenticated Endpoints (USER role)

- `GET /products`: Product catalog with search
- `POST /products/search`: Product search (SQLi/XSS detection)
- `GET /cart`: Shopping cart view
- `POST /cart/add`: Add item to cart
- `POST /cart/update`: Update cart quantities
- `GET /checkout`: Checkout form
- `POST /checkout/submit`: Payment processing
- `GET /confirmation`: Order confirmation

### Admin Endpoints (ADMIN role)

- `GET /api/security/dashboard`: Security metrics dashboard (JSON)
- `GET /api/security/events`: Recent security events (JSON)
- `GET /api/security/stats`: Statistics summary (JSON)

### Development Endpoints (Demo profile)

- `GET /h2-console`: H2 database console (JDBC URL: `jdbc:h2:file:../data/security-events`)

## Database Schema

### security_events

```sql
CREATE TABLE security_events (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    event_type VARCHAR(50) NOT NULL,           -- SQL_INJECTION_ATTEMPT, XSS_ATTEMPT, etc.
    severity VARCHAR(20) NOT NULL,             -- INFO, LOW, MEDIUM, HIGH, CRITICAL
    username VARCHAR(100),                     -- Affected user account
    session_id VARCHAR(255),                   -- HTTP session ID
    ip_address VARCHAR(45),                    -- Source IP address
    user_agent VARCHAR(500),                   -- Browser/client identifier
    description TEXT,                          -- Event details
    successful BOOLEAN,                        -- Attack success indicator
    timestamp TIMESTAMP NOT NULL,              -- Event occurrence time
    additional_data TEXT                       -- JSON/structured metadata
);

-- Indexes for SIEM query performance
CREATE INDEX idx_event_type ON security_events(event_type);
CREATE INDEX idx_severity ON security_events(severity);
CREATE INDEX idx_username ON security_events(username);
CREATE INDEX idx_timestamp ON security_events(timestamp);
```

### authentication_attempts

```sql
CREATE TABLE authentication_attempts (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) NOT NULL,
    success BOOLEAN NOT NULL,
    ip_address VARCHAR(45),
    failure_reason VARCHAR(200),
    attempt_timestamp TIMESTAMP NOT NULL
);

CREATE INDEX idx_username_time ON authentication_attempts(username, attempt_timestamp);
CREATE INDEX idx_success ON authentication_attempts(success);
```

### transaction_anomalies

```sql
CREATE TABLE transaction_anomalies (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    transaction_id VARCHAR(100),
    username VARCHAR(100),
    anomaly_type VARCHAR(50) NOT NULL,         -- AMOUNT_TAMPERING, CART_MANIPULATION
    original_amount DECIMAL(10,2),
    modified_amount DECIMAL(10,2),
    anomaly_details TEXT,
    detection_timestamp TIMESTAMP NOT NULL
);

CREATE INDEX idx_anomaly_type ON transaction_anomalies(anomaly_type);
CREATE INDEX idx_tx_username ON transaction_anomalies(username);
```

## CI/CD Integration

### GitHub Actions Workflows

**Security Test Workflow** (`.github/workflows/security-tests.yml`):

```yaml
# Triggers: Push to main, Pull requests, Manual dispatch
# Steps:
#   1. Checkout code
#   2. Setup Java 21
#   3. Setup Python 3.9
#   4. Install Python dependencies
#   5. Build Spring Boot application
#   6. Start application in background
#   7. Run TestNG security test suite (headless)
#   8. Run SIEM analysis on test results
#   9. Upload test reports as artifacts
```

**Manual JIRA Workflow** (`.github/workflows/manual-jira-tickets.yml`):

```yaml
# Trigger: Manual workflow dispatch
# Inputs: JIRA credentials (secrets)
# Steps:
#   1. Checkout code
#   2. Setup Python
#   3. Run SIEM analysis
#   4. Create JIRA tickets from incidents
```

## Development Guidelines

### Adding New Security Event Types

1. **Add to SecurityEventLogger allowed types**:

```java
private static final Set<String> ALLOWED_EVENT_TYPES = Set.of(
    // ... existing types
    "NEW_EVENT_TYPE"
);
```

2. **Log events in application code**:

```java
@Autowired
private SecurityEventService securityEventService;

securityEventService.logSecurityEvent(
    "NEW_EVENT_TYPE",
    "HIGH",
    username,
    sessionId,
    "Event description"
);
```

3. **Update SIEM analyzer patterns** (`security_analyzer_h2.py`):

```python
def detect_new_pattern(events):
    # Add correlation logic
    pass
```

### Creating New Attack Tests

1. **Extend BaseTest**:

```java
public class NewAttackTest extends BaseTest {
    @Test(description = "Test description")
    public void testAttackScenario() {
        // Selenium automation
        driver.get(baseUrl + "/endpoint");
        
        // Perform attack
        // ...
        
        // Verify detection
        Assert.assertTrue(
            eventLogger.waitForEvent("EVENT_TYPE", testStart, Duration.ofSeconds(10))
        );
    }
}
```

2. **Add to testng.xml**:

```xml
<test name="New Attack Test">
    <classes>
        <class name="com.security.tests.category.NewAttackTest"/>
    </classes>
</test>
```

## Performance Metrics

### Application Startup

- **Cold Start**: ~8-12 seconds (Spring Boot initialization)
- **Warm Start**: ~5-7 seconds (JVM already running)

### Test Execution

- **Full Suite**: 47+ tests in ~4-6 minutes (parallel execution, 5 threads, headless mode)
- **Single Test**: ~5-15 seconds (depends on Selenium interactions)
- **Race Condition Tests**: ~20-30 seconds (concurrent ExecutorService operations)

### SIEM Analysis

- **100 events**: <1 second
- **1,000 events**: ~2-3 seconds
- **10,000 events**: ~15-20 seconds (JDBC query + Python processing)

## Troubleshooting

### Port Already in Use (8080)

```powershell
# Find process using port 8080
Get-NetTCPConnection -LocalPort 8080 | Select-Object OwningProcess

# Kill process
Stop-Process -Id <PID> -Force
```

### H2 Database Lock

```powershell
# Delete lock files
Remove-Item data/security-events.*.db -Force
```

### Chrome Driver Issues

```bash
# WebDriverManager auto-downloads drivers, but manual installation:
# 1. Check Chrome version: chrome://version
# 2. Download matching ChromeDriver from https://chromedriver.chromium.org
# 3. Add to PATH or specify in test properties
```

### Python JDBC Connection Errors

```bash
# Ensure JAVA_HOME is set
echo $env:JAVA_HOME

# Install correct Java version (JPype1 requires JDK)
# Verify H2 database file exists: data/security-events.mv.db
```

## Security Internship Interview Talking Points

### Technical Depth

- **Runtime Detection**: Pattern-based SQLi/XSS detection vs static analysis
- **SIEM Integration**: Event correlation vs simple logging
- **Defense in Depth**: Multiple layers (input validation, parameterized queries, WAF-like detection)
- **Performance Trade-offs**: In-memory rate limiting vs distributed solutions (Redis)

### Design Decisions

- **File-based H2**: Simplicity for demo vs production PostgreSQL/MySQL
- **Cookie-based CSRF**: Stateless tokens vs synchronizer token pattern
- **BCrypt Cost Factor**: Balance security (cost=10) vs login performance
- **Sliding Window Rate Limiting**: Accuracy vs memory efficiency

### Real-world Applications

- **SIEM Correlation**: Similar to Splunk, ELK, Azure Sentinel
- **Incident Response**: JIRA integration mirrors SOC workflows
- **Attack Simulation**: Similar to purple team exercises
- **Continuous Testing**: CI/CD integration for security regression testing

### Phase 2 Enhancements (Implemented)

- **Cryptographic Testing**: TLS enforcement, HSTS validation, secure cookie attributes, client-side data exposure
- **Race Condition Detection**: Concurrent cart operations, double checkout vulnerabilities using ExecutorService
- **Advanced Rate Limiting**: Bypass detection for IP spoofing, session rotation, slowloris-style attacks
- **Error Handling Security**: Stack trace exposure, OPTIONS method information leakage
- **Comprehensive OWASP Coverage**: 8/10 categories (80%) with runtime DAST approach

### Future Enhancements

- **Machine Learning**: Anomaly detection for zero-day attacks
- **Distributed Tracing**: OpenTelemetry for microservices
- **WAF Integration**: ModSecurity or cloud WAF (CloudFlare, AWS WAF)
- **Threat Intelligence**: STIX/TAXII feed integration
- **A06 Coverage**: OWASP Dependency-Check integration in CI/CD
- **A08 Coverage**: Software Bill of Materials (SBOM), artifact signature verification

## License

MIT License - See LICENSE file for details

## Author

Security Engineering Demo Project for Internship Interview

## References

- [OWASP Top 10 2021](https://owasp.org/www-project-top-ten/)
- [Spring Security Documentation](https://docs.spring.io/spring-security/reference/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
