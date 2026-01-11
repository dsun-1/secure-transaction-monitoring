# Secure E-Commerce Transaction Monitor Details

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
- **Test Classes**: 16 active test classes
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
    event_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    username VARCHAR(100),
    session_id VARCHAR(255),
    ip_address VARCHAR(45),
    user_agent VARCHAR(500),
    description TEXT,
    successful BOOLEAN,
    timestamp TIMESTAMP NOT NULL,
    additional_data TEXT
);

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
    anomaly_type VARCHAR(50) NOT NULL,
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
