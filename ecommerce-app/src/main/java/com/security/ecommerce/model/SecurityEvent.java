package com.security.ecommerce.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * Security Event entity for logging authentication and authorization events
 * Used for threat detection and incident response
 */
@Entity
@Table(name = "security_events")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class SecurityEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Enumerated(EnumType.STRING)
    private EventType eventType;

    private String username;

    private String ipAddress;

    private String sessionId;

    private String userAgent;

    @Enumerated(EnumType.STRING)
    private EventSeverity severity;

    private String description;

    private boolean successful;

    private LocalDateTime timestamp = LocalDateTime.now();

    private String additionalData;

    public enum EventType {
        LOGIN_ATTEMPT,
        LOGIN_SUCCESS,
        LOGIN_FAILURE,
        LOGOUT,
        ACCOUNT_LOCKED,
        PASSWORD_CHANGE,
        PRIVILEGE_ESCALATION_ATTEMPT,
        SUSPICIOUS_ACTIVITY,
        BRUTE_FORCE_DETECTED,
        SQL_INJECTION_ATTEMPT,
        XSS_ATTEMPT,
        CSRF_VIOLATION,
        SESSION_HIJACK_ATTEMPT,
        INVALID_PAYMENT,
        AMOUNT_TAMPERING,
        CART_MANIPULATION,
        COUPON_ABUSE
    }

    public enum EventSeverity {
        INFO,
        LOW,
        MEDIUM,
        HIGH,
        CRITICAL
    }

    // Factory methods for common events
    public static SecurityEvent loginFailure(String username, String ipAddress, String sessionId) {
        SecurityEvent event = new SecurityEvent();
        event.setEventType(EventType.LOGIN_FAILURE);
        event.setUsername(username);
        event.setIpAddress(ipAddress);
        event.setSessionId(sessionId);
        event.setSeverity(EventSeverity.MEDIUM);
        event.setSuccessful(false);
        event.setDescription("Failed login attempt for user: " + username);
        return event;
    }

    public static SecurityEvent bruteForceDetected(String username, String ipAddress, int attemptCount) {
        SecurityEvent event = new SecurityEvent();
        event.setEventType(EventType.BRUTE_FORCE_DETECTED);
        event.setUsername(username);
        event.setIpAddress(ipAddress);
        event.setSeverity(EventSeverity.CRITICAL);
        event.setSuccessful(false);
        event.setDescription("Brute force attack detected: " + attemptCount + " attempts");
        return event;
    }

    public static SecurityEvent suspiciousTransaction(String username, String reason) {
        SecurityEvent event = new SecurityEvent();
        event.setEventType(EventType.SUSPICIOUS_ACTIVITY);
        event.setUsername(username);
        event.setSeverity(EventSeverity.HIGH);
        event.setSuccessful(false);
        event.setDescription("Suspicious transaction activity: " + reason);
        return event;
    }
}
