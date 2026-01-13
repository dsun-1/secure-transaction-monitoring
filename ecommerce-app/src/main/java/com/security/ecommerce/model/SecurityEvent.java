package com.security.ecommerce.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;


@Entity
@Table(name = "security_events")
@Data
@NoArgsConstructor
@AllArgsConstructor
// security event entity stored for analysis
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

    // event categories used by detections and reporting
    public enum EventType {
        LOGIN_ATTEMPT,
        LOGIN_SUCCESS,
        LOGIN_FAILURE,
        LOGOUT,
        ACCOUNT_LOCKED,
        ACCOUNT_ENUMERATION,
        BOT_REGISTRATION_ATTEMPT,
        PASSWORD_CHANGE,
        ACCESS_CONTROL_VIOLATION,
        PRIVILEGE_ESCALATION_ATTEMPT,
        SUSPICIOUS_ACTIVITY,
        BRUTE_FORCE_DETECTED,
        BRUTE_FORCE_PREVENTION_SUCCESS,
        DISTRIBUTED_BRUTE_FORCE,
        CREDENTIAL_STUFFING,
        SQL_INJECTION_ATTEMPT,
        SSRF_ATTEMPT,
        XSS_ATTEMPT,
        CSRF_VIOLATION,
        SESSION_HIJACK_ATTEMPT,
        SESSION_FIXATION_ATTEMPT,
        API_AUTH_FAILURE,
        RATE_LIMIT_EXCEEDED,
        INVALID_PAYMENT,
        AMOUNT_TAMPERING,
        CART_MANIPULATION,
        COUPON_ABUSE,
        RACE_CONDITION_DETECTED,
        TRANSACTION_ANOMALY,
        SECURITY_HEADERS_MISSING,
        UNSAFE_HTTP_METHOD,
        INFO_DISCLOSURE,
        SECURITY_MISCONFIGURATION,
        CRYPTOGRAPHIC_FAILURE,
        DESERIALIZATION_ATTEMPT,
        SOFTWARE_INTEGRITY_VIOLATION,
        VULNERABLE_COMPONENTS
    }

    // severity levels used for alerting
    public enum EventSeverity {
        INFO,
        LOW,
        MEDIUM,
        HIGH,
        CRITICAL
    }
}
