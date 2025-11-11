package com.security.tests.utils;

import java.sql.*;
import java.time.LocalDateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Security Event Logger - Captures authentication events, failed logins,
 * and transaction anomalies into a SQL database for analysis.
 */
public class SecurityEventLogger {
    
    private static final Logger logger = LoggerFactory.getLogger(SecurityEventLogger.class);
    private static final String DB_URL = "jdbc:h2:./data/security-events;AUTO_SERVER=TRUE";
    private static final String DB_USER = "sa";
    private static final String DB_PASSWORD = "";
    
    public static void initializeDatabase() {
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
             Statement stmt = conn.createStatement()) {
            
            // Create security_events table
            String createTable = """
                CREATE TABLE IF NOT EXISTS security_events (
                    id BIGINT AUTO_INCREMENT PRIMARY KEY,
                    event_type VARCHAR(50) NOT NULL,
                    severity VARCHAR(20) NOT NULL,
                    username VARCHAR(100),
                    session_id VARCHAR(255),
                    ip_address VARCHAR(45),
                    user_agent VARCHAR(500),
                    event_details TEXT,
                    suspected_threat VARCHAR(100),
                    timestamp TIMESTAMP NOT NULL
                );
            """;
            
            stmt.execute(createTable);
            
            // Create indexes separately
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_event_type ON security_events(event_type)");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_severity ON security_events(severity)");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_username ON security_events(username)");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON security_events(timestamp)");
            
            // Create authentication_attempts table
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
            
            // Create transaction_anomalies table
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
        String sql = """
            INSERT INTO security_events 
            (event_type, severity, username, session_id, ip_address, user_agent, 
             event_details, suspected_threat, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """;
        
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setString(1, event.getEventType());
            pstmt.setString(2, event.getSeverity());
            pstmt.setString(3, event.getUsername());
            pstmt.setString(4, event.getSessionId());
            pstmt.setString(5, event.getIpAddress());
            pstmt.setString(6, event.getUserAgent());
            pstmt.setString(7, event.getEventDetails());
            pstmt.setString(8, event.getSuspectedThreat());
            pstmt.setTimestamp(9, Timestamp.valueOf(event.getTimestamp()));
            
            pstmt.executeUpdate();
            logger.debug("Logged security event: {} - {}", event.getEventType(), event.getSeverity());
            
        } catch (SQLException e) {
            logger.error("Failed to log security event", e);
        }
    }
    
    public void logAuthenticationAttempt(String username, boolean success, 
                                        String ipAddress, String failureReason) {
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
