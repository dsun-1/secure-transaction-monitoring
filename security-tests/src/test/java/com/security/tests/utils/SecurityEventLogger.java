package com.security.tests.utils;

import java.sql.*;
import java.time.LocalDateTime;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Locale;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


// writes test-generated security events into the h2 demo siem store
public class SecurityEventLogger {
    
    private static final Logger logger = LoggerFactory.getLogger(SecurityEventLogger.class);
    // shared db path so app and tests write to the same event store
    private static final String DB_PATH = "../ecommerce-app/data/security-events";
    private static final String DB_URL = "jdbc:h2:" + DB_PATH + ";AUTO_SERVER=TRUE";
    private static final String DB_USER = "sa";
    private static final String DB_PASSWORD = "";
    // keep event types normalized to match app enums and analyzer queries
    private static final Set<String> ALLOWED_EVENT_TYPES = Set.of(
        "ACCOUNT_LOCKED",
        "AMOUNT_TAMPERING",
        "BRUTE_FORCE_DETECTED",
        "CART_MANIPULATION",
        "COUPON_ABUSE",
        "CSRF_VIOLATION",
        "INVALID_PAYMENT",
        "LOGIN_ATTEMPT",
        "LOGIN_FAILURE",
        "LOGIN_SUCCESS",
        "LOGOUT",
        "PASSWORD_CHANGE",
        "PRIVILEGE_ESCALATION_ATTEMPT",
        "SESSION_HIJACK_ATTEMPT",
        "SQL_INJECTION_ATTEMPT",
        "SUSPICIOUS_ACTIVITY",
        "XSS_ATTEMPT"
    );
    // normalized severities so analytics can key on consistent values
    private static final Set<String> ALLOWED_SEVERITIES = Set.of(
        "INFO",
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL"
    );
    
    public static void initializeDatabase() {
        // create local db directory and tables for event storage
        try {
            Path dbDir = Paths.get("../ecommerce-app/data");
            Files.createDirectories(dbDir);
        } catch (Exception e) {
            logger.warn("Unable to ensure H2 data directory exists: {}", e.getMessage());
        }
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
             Statement stmt = conn.createStatement()) {
            
            
            // core security event table used by siem analyzer
            String createTable = """
                CREATE TABLE IF NOT EXISTS security_events (
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
            """;
            
            stmt.execute(createTable);
            
            
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_event_type ON security_events(event_type)");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_severity ON security_events(severity)");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_username ON security_events(username)");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON security_events(timestamp)");
            
            
            // login attempt history used for brute-force analysis
            String createAuthTable = """
                CREATE TABLE IF NOT EXISTS authentication_attempts (
                    id BIGINT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(100) NOT NULL,
                    success BOOLEAN NOT NULL,
                    ip_address VARCHAR(45),
                    failure_reason VARCHAR(200),
                    attempt_timestamp TIMESTAMP NOT NULL
                );
            """;
            
            stmt.execute(createAuthTable);
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_username_time ON authentication_attempts(username, attempt_timestamp)");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_success ON authentication_attempts(success)");
            
            
            // anomaly table used for transaction tampering signals
            String createTxTable = """
                CREATE TABLE IF NOT EXISTS transaction_anomalies (
                    id BIGINT AUTO_INCREMENT PRIMARY KEY,
                    transaction_id VARCHAR(100),
                    username VARCHAR(100),
                    anomaly_type VARCHAR(50) NOT NULL,
                    original_amount DECIMAL(10,2),
                    modified_amount DECIMAL(10,2),
                    anomaly_details TEXT,
                    detection_timestamp TIMESTAMP NOT NULL
                );
            """;
            
            stmt.execute(createTxTable);
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_anomaly_type ON transaction_anomalies(anomaly_type)");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_tx_username ON transaction_anomalies(username)");
            
            logger.info("Security events database initialized successfully");
            
        } catch (SQLException e) {
            logger.error("Failed to initialize security events database", e);
        }
    }
    
    public void logSecurityEvent(SecurityEvent event) {
        // insert a normalized event record for downstream detection
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
             PreparedStatement pstmt = conn.prepareStatement(buildInsertSql(conn))) {
            
            boolean usesDescription = usesDescriptionColumns(conn);
            String mappedEventType = mapEventType(event.getEventType());
            String mappedSeverity = mapSeverity(event.getSeverity());
            boolean successful = "INFO".equalsIgnoreCase(mappedSeverity)
                || "LOW".equalsIgnoreCase(mappedSeverity);
            String description = event.getEventDetails();
            String additionalData = event.getSuspectedThreat();
            if (event.getEventType() != null
                && !mappedEventType.equals(event.getEventType().trim().toUpperCase(Locale.ROOT))) {
                additionalData = appendAdditional(additionalData, "original_event_type=" + event.getEventType());
            }
            if (event.getSeverity() != null
                && !mappedSeverity.equals(event.getSeverity().trim().toUpperCase(Locale.ROOT))) {
                additionalData = appendAdditional(additionalData, "original_severity=" + event.getSeverity());
            }
            
            pstmt.setString(1, mappedEventType);
            pstmt.setString(2, mappedSeverity);
            pstmt.setString(3, event.getUsername());
            pstmt.setString(4, event.getSessionId());
            pstmt.setString(5, event.getIpAddress());
            pstmt.setString(6, event.getUserAgent());
            if (usesDescription) {
                pstmt.setString(7, description);
                pstmt.setBoolean(8, successful);
                pstmt.setTimestamp(9, Timestamp.valueOf(event.getTimestamp()));
                pstmt.setString(10, additionalData);
            } else {
                pstmt.setString(7, description);
                pstmt.setString(8, additionalData);
                pstmt.setTimestamp(9, Timestamp.valueOf(event.getTimestamp()));
            }
            
            pstmt.executeUpdate();
            logger.debug("Logged security event: {} - {}", event.getEventType(), event.getSeverity());
            
        } catch (SQLException e) {
            logger.error("Failed to log security event", e);
        }
    }

    // map arbitrary event labels to the allowed enum values
    private String mapEventType(String rawEventType) {
        if (rawEventType == null || rawEventType.isBlank()) {
            return "SUSPICIOUS_ACTIVITY";
        }
        String normalized = rawEventType.trim().toUpperCase(Locale.ROOT);
        if (ALLOWED_EVENT_TYPES.contains(normalized)) {
            return normalized;
        }
        if (normalized.contains("SQL")) {
            return "SQL_INJECTION_ATTEMPT";
        }
        if (normalized.contains("XSS")) {
            return "XSS_ATTEMPT";
        }
        if (normalized.contains("CSRF")) {
            return "CSRF_VIOLATION";
        }
        if (normalized.contains("BRUTE_FORCE") || normalized.contains("CREDENTIAL")) {
            return "BRUTE_FORCE_DETECTED";
        }
        if (normalized.contains("SESSION")) {
            return "SESSION_HIJACK_ATTEMPT";
        }
        if (normalized.contains("CART")) {
            return "CART_MANIPULATION";
        }
        if (normalized.contains("AMOUNT") || normalized.contains("PRICE")) {
            return "AMOUNT_TAMPERING";
        }
        if (normalized.contains("PAYMENT")) {
            return "INVALID_PAYMENT";
        }
        if (normalized.contains("PRIVILEGE")) {
            return "PRIVILEGE_ESCALATION_ATTEMPT";
        }
        if (normalized.contains("PASSWORD")) {
            return "PASSWORD_CHANGE";
        }
        if (normalized.contains("LOGOUT")) {
            return "LOGOUT";
        }
        if (normalized.contains("LOGIN") && normalized.contains("FAIL")) {
            return "LOGIN_FAILURE";
        }
        if (normalized.contains("LOGIN") && normalized.contains("SUCCESS")) {
            return "LOGIN_SUCCESS";
        }
        if (normalized.contains("LOGIN")) {
            return "LOGIN_ATTEMPT";
        }
        return "SUSPICIOUS_ACTIVITY";
    }

    // map free-form severity to a known tier
    private String mapSeverity(String rawSeverity) {
        if (rawSeverity == null || rawSeverity.isBlank()) {
            return "LOW";
        }
        String normalized = rawSeverity.trim().toUpperCase(Locale.ROOT);
        if (ALLOWED_SEVERITIES.contains(normalized)) {
            return normalized;
        }
        if ("WARN".equals(normalized) || "WARNING".equals(normalized)) {
            return "MEDIUM";
        }
        return "LOW";
    }

    private String appendAdditional(String existing, String addition) {
        if (addition == null || addition.isBlank()) {
            return existing;
        }
        if (existing == null || existing.isBlank()) {
            return addition;
        }
        return existing + " | " + addition;
    }

    // detect legacy vs current schema column names
    private boolean usesDescriptionColumns(Connection conn) throws SQLException {
        return columnExists(conn, "SECURITY_EVENTS", "DESCRIPTION")
            && columnExists(conn, "SECURITY_EVENTS", "ADDITIONAL_DATA")
            && columnExists(conn, "SECURITY_EVENTS", "SUCCESSFUL");
    }

    // pick insert statement based on schema shape
    private String buildInsertSql(Connection conn) throws SQLException {
        if (usesDescriptionColumns(conn)) {
            return """
                INSERT INTO security_events
                (event_type, severity, username, session_id, ip_address, user_agent,
                 description, successful, timestamp, additional_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """;
        }
        return """
            INSERT INTO security_events
            (event_type, severity, username, session_id, ip_address, user_agent,
             event_details, suspected_threat, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """;
    }

    private boolean columnExists(Connection conn, String tableName, String columnName) throws SQLException {
        DatabaseMetaData metaData = conn.getMetaData();
        try (ResultSet rs = metaData.getColumns(null, null, tableName.toUpperCase(), columnName.toUpperCase())) {
            return rs.next();
        }
    }
    
    public void logAuthenticationAttempt(String username, boolean success, 
                                        String ipAddress, String failureReason) {
        // store auth attempts for brute-force correlation
        String sql = """
            INSERT INTO authentication_attempts 
            (username, success, ip_address, failure_reason, attempt_timestamp)
            VALUES (?, ?, ?, ?, ?)
        """;
        
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setString(1, username);
            pstmt.setBoolean(2, success);
            pstmt.setString(3, ipAddress);
            pstmt.setString(4, failureReason);
            pstmt.setTimestamp(5, Timestamp.valueOf(LocalDateTime.now()));
            
            pstmt.executeUpdate();
            
        } catch (SQLException e) {
            logger.error("Failed to log authentication attempt", e);
        }
    }
    
    public void logTransactionAnomaly(String transactionId, String username, 
                                     String anomalyType, Double originalAmount, 
                                     Double modifiedAmount, String details) {
        // store transaction anomalies for fraud-style detection
        String sql = """
            INSERT INTO transaction_anomalies 
            (transaction_id, username, anomaly_type, original_amount, 
             modified_amount, anomaly_details, detection_timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """;
        
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setString(1, transactionId);
            pstmt.setString(2, username);
            pstmt.setString(3, anomalyType);
            pstmt.setDouble(4, originalAmount);
            pstmt.setDouble(5, modifiedAmount);
            pstmt.setString(6, details);
            pstmt.setTimestamp(7, Timestamp.valueOf(LocalDateTime.now()));
            
            pstmt.executeUpdate();
            logger.warn("Transaction anomaly detected: {} for user {}", anomalyType, username);
            
        } catch (SQLException e) {
            logger.error("Failed to log transaction anomaly", e);
        }
    }
}
