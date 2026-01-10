package com.security.ecommerce.service;

import com.security.ecommerce.model.SecurityEvent;
import com.security.ecommerce.repository.SecurityEventRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.jdbc.core.JdbcTemplate;
import jakarta.annotation.PostConstruct;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Deque;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;

@Service
@Transactional
// central logger for security telemetry; feeds the siem analysis pipeline
public class SecurityEventService {
    
    private static final Logger logger = LoggerFactory.getLogger(SecurityEventService.class);
    private static final Duration SIGNAL_WINDOW = Duration.ofMinutes(5);
    private static final Duration SIGNAL_THROTTLE = Duration.ofMinutes(5);
    
    private final SecurityEventRepository securityEventRepository;
    private final JdbcTemplate jdbcTemplate;
    private final Deque<LoginAttempt> failedAttempts = new ConcurrentLinkedDeque<>();
    private final ConcurrentHashMap<String, LocalDateTime> lastSignals = new ConcurrentHashMap<>();

    public SecurityEventService(SecurityEventRepository securityEventRepository,
                                JdbcTemplate jdbcTemplate) {
        this.securityEventRepository = securityEventRepository;
        this.jdbcTemplate = jdbcTemplate;
    }

    @PostConstruct
    public void ensureAuxTables() {
        jdbcTemplate.execute("""
            CREATE TABLE IF NOT EXISTS authentication_attempts (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(100) NOT NULL,
                success BOOLEAN NOT NULL,
                ip_address VARCHAR(45),
                failure_reason VARCHAR(200),
                attempt_timestamp TIMESTAMP NOT NULL
            )
        """);
        jdbcTemplate.execute("""
            CREATE TABLE IF NOT EXISTS transaction_anomalies (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,
                transaction_id VARCHAR(100),
                username VARCHAR(100),
                anomaly_type VARCHAR(50) NOT NULL,
                original_amount DECIMAL(10,2),
                modified_amount DECIMAL(10,2),
                anomaly_details TEXT,
                detection_timestamp TIMESTAMP NOT NULL
            )
        """);
    }
    
    
    
    
    
    
    // persist any security event and emit a structured audit log entry
    public SecurityEvent logEvent(SecurityEvent event) {
        if (event.getTimestamp() == null) {
            event.setTimestamp(LocalDateTime.now());
        }
        SecurityEvent saved = securityEventRepository.save(event);
        logger.info("Security Event Logged: {} - {} - {}", 
            event.getEventType(), event.getSeverity(), event.getDescription());
        
        
        
        
        
        
        return saved;
    }
    
    // standardizes login success/failure events for auth monitoring
    public SecurityEvent logAuthenticationAttempt(String username, String ipAddress, 
                                                   boolean successful, String userAgent) {
        SecurityEvent event = new SecurityEvent();
        event.setEventType(successful ? SecurityEvent.EventType.LOGIN_SUCCESS : 
                                        SecurityEvent.EventType.LOGIN_FAILURE);
        event.setUsername(username);
        event.setIpAddress(ipAddress);
        event.setUserAgent(userAgent);
        event.setSuccessful(successful);
        event.setSeverity(successful ? SecurityEvent.EventSeverity.LOW : 
                                      SecurityEvent.EventSeverity.MEDIUM);
        event.setDescription(successful ? "Successful login" : "Failed login attempt");
        event.setTimestamp(LocalDateTime.now());
        SecurityEvent saved = logEvent(event);
        recordAuthenticationAttempt(username, successful, ipAddress,
            successful ? null : "Failed login attempt");
        if (!successful) {
            recordFailedLoginSignals(username, ipAddress);
        }
        return saved;
    }
    
    // convenience wrapper for high-severity alerts used by tests and detections
    public SecurityEvent logHighSeverityEvent(String eventType, String username, 
                                               String description, String additionalData) {
        SecurityEvent.EventType resolvedType = resolveEventType(eventType);
        String normalizedAdditionalData = additionalData;
        if (resolvedType == SecurityEvent.EventType.SUSPICIOUS_ACTIVITY
            && eventType != null
            && !eventType.isBlank()) {
            String marker = "event_type=" + eventType;
            if (normalizedAdditionalData == null || normalizedAdditionalData.isBlank()) {
                normalizedAdditionalData = marker;
            } else {
                normalizedAdditionalData = marker + " | " + normalizedAdditionalData;
            }
        }

        SecurityEvent event = new SecurityEvent();
        event.setEventType(resolvedType);
        event.setUsername(username);
        event.setSeverity(SecurityEvent.EventSeverity.HIGH);
        event.setDescription(description);
        event.setAdditionalData(normalizedAdditionalData);
        event.setSuccessful(false);
        event.setTimestamp(LocalDateTime.now());
        
        return logEvent(event);
    }
    
    // used by dashboards or siem queries to pull recent critical activity
    public List<SecurityEvent> getRecentHighSeverityEvents(int hours) {
        LocalDateTime since = LocalDateTime.now().minusHours(hours);
        return securityEventRepository.findHighSeverityEventsSince(since);
    }
    
    // admin-level view of all security events
    public List<SecurityEvent> getAllEvents() {
        return securityEventRepository.findAll();
    }

    public void recordAuthenticationAttempt(String username, boolean success,
                                            String ipAddress, String failureReason) {
        jdbcTemplate.update(
            """
                INSERT INTO authentication_attempts
                (username, success, ip_address, failure_reason, attempt_timestamp)
                VALUES (?, ?, ?, ?, ?)
            """,
            username,
            success,
            ipAddress,
            failureReason,
            java.sql.Timestamp.valueOf(LocalDateTime.now())
        );
    }

    public void recordTransactionAnomaly(String transactionId, String username,
                                         String anomalyType, double originalAmount,
                                         double modifiedAmount, String details) {
        jdbcTemplate.update(
            """
                INSERT INTO transaction_anomalies
                (transaction_id, username, anomaly_type, original_amount, modified_amount,
                 anomaly_details, detection_timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            transactionId,
            username,
            anomalyType,
            originalAmount,
            modifiedAmount,
            details,
            java.sql.Timestamp.valueOf(LocalDateTime.now())
        );
    }

    private SecurityEvent.EventType resolveEventType(String eventType) {
        if (eventType == null || eventType.isBlank()) {
            return SecurityEvent.EventType.SUSPICIOUS_ACTIVITY;
        }
        try {
            return SecurityEvent.EventType.valueOf(eventType.trim().toUpperCase());
        } catch (IllegalArgumentException ex) {
            return SecurityEvent.EventType.SUSPICIOUS_ACTIVITY;
        }
    }

    private void recordFailedLoginSignals(String username, String ipAddress) {
        LocalDateTime now = LocalDateTime.now();
        failedAttempts.addLast(new LoginAttempt(username, ipAddress, now));
        pruneOldAttempts(now);

        int userFailures = 0;
        Set<String> userIps = new HashSet<>();
        Set<String> ipUsernames = new HashSet<>();
        for (LoginAttempt attempt : failedAttempts) {
            if (attempt.timestamp.isBefore(now.minus(SIGNAL_WINDOW))) {
                continue;
            }
            if (attempt.username != null && attempt.username.equals(username)) {
                userFailures++;
                if (attempt.ipAddress != null) {
                    userIps.add(attempt.ipAddress);
                }
            }
            if (ipAddress != null && ipAddress.equals(attempt.ipAddress) && attempt.username != null) {
                ipUsernames.add(attempt.username);
            }
        }

        if (userFailures >= 5) {
            emitThrottledSignal("BRUTE_FORCE_DETECTED", username, "Repeated failed logins detected",
                "count=" + userFailures + " | ip=" + ipAddress);
        }
        if (userFailures >= 10 || userIps.size() >= 3) {
            emitThrottledSignal("DISTRIBUTED_BRUTE_FORCE", username, "Failed logins across multiple sources",
                "count=" + userFailures + " | unique_ips=" + userIps.size());
        }
        if (ipUsernames.size() >= 4) {
            emitThrottledSignal("CREDENTIAL_STUFFING", username, "Multiple usernames failed from same source",
                "unique_users=" + ipUsernames.size() + " | ip=" + ipAddress);
        }
    }

    private void emitThrottledSignal(String eventType, String username, String description, String additional) {
        LocalDateTime now = LocalDateTime.now();
        String key = eventType + ":" + username;
        LocalDateTime last = lastSignals.get(key);
        if (last != null && last.isAfter(now.minus(SIGNAL_THROTTLE))) {
            return;
        }
        lastSignals.put(key, now);
        logHighSeverityEvent(eventType, username != null ? username : "unknown", description, additional);
    }

    private void pruneOldAttempts(LocalDateTime now) {
        LocalDateTime cutoff = now.minus(SIGNAL_WINDOW);
        while (!failedAttempts.isEmpty()) {
            LoginAttempt attempt = failedAttempts.peekFirst();
            if (attempt == null || !attempt.timestamp.isBefore(cutoff)) {
                break;
            }
            failedAttempts.pollFirst();
        }
    }

    private record LoginAttempt(String username, String ipAddress, LocalDateTime timestamp) {}
}
