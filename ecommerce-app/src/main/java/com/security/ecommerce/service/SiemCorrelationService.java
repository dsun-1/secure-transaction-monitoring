package com.security.ecommerce.service;

import com.security.ecommerce.model.SecurityEvent;
import com.security.ecommerce.repository.SecurityEventRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * SIEM Correlation Service
 * Analyzes security events for patterns and correlations
 * Detects: Brute force attacks, distributed attacks, privilege escalation
 */
@Service
public class SiemCorrelationService {
    
    private static final Logger logger = LoggerFactory.getLogger(SiemCorrelationService.class);
    
    private final SecurityEventRepository eventRepository;
    private final AlertManagerService alertManager;
    
    // Thresholds for attack detection
    private static final int BRUTE_FORCE_THRESHOLD = 5;
    private static final int DISTRIBUTED_ATTACK_THRESHOLD = 10;
    private static final int TIME_WINDOW_MINUTES = 15;
    
    public SiemCorrelationService(SecurityEventRepository eventRepository,
                                   AlertManagerService alertManager) {
        this.eventRepository = eventRepository;
        this.alertManager = alertManager;
    }
    
    /**
     * Periodically analyze events for security threats
     * Runs every 5 minutes
     */
    @Scheduled(fixedRate = 300000)
    public void analyzeSecurityEvents() {
        logger.debug("🔍 Running SIEM correlation analysis...");
        
        LocalDateTime since = LocalDateTime.now().minusMinutes(TIME_WINDOW_MINUTES);
        
        detectBruteForceAttacks(since);
        detectDistributedAttacks(since);
        detectPrivilegeEscalation(since);
    }
    
    /**
     * Detect brute force login attempts
     */
    private void detectBruteForceAttacks(LocalDateTime since) {
        try {
            List<SecurityEvent> loginFailures = eventRepository
                .findByEventTypeAndTimestampAfter(SecurityEvent.EventType.LOGIN_FAILURE, since);
            
            // Group by username
            Map<String, Long> failuresByUser = new HashMap<>();
            for (SecurityEvent event : loginFailures) {
                String username = event.getUsername();
                if (username != null) {
                    failuresByUser.put(username, failuresByUser.getOrDefault(username, 0L) + 1);
                }
            }
            
            // Check for brute force attempts
            for (Map.Entry<String, Long> entry : failuresByUser.entrySet()) {
                if (entry.getValue() >= BRUTE_FORCE_THRESHOLD) {
                    SecurityEvent alert = SecurityEvent.bruteForceDetected(
                        entry.getKey(), 
                        "CORRELATION_ENGINE", 
                        entry.getValue().intValue()
                    );
                    eventRepository.save(alert);
                    alertManager.sendAlert(alert);
                    
                    logger.warn("⚠️ BRUTE FORCE ATTACK DETECTED: User={} Attempts={}", 
                        entry.getKey(), entry.getValue());
                }
            }
        } catch (Exception e) {
            logger.error("Error detecting brute force attacks: {}", e.getMessage());
        }
    }
    
    /**
     * Detect distributed attacks (same attack type from multiple IPs)
     */
    private void detectDistributedAttacks(LocalDateTime since) {
        try {
            // Check for SQL injection attempts from multiple sources
            List<SecurityEvent> sqlInjectionEvents = eventRepository
                .findByEventTypeAndTimestampAfter(SecurityEvent.EventType.SQL_INJECTION_ATTEMPT, since);
            
            long uniqueIps = sqlInjectionEvents.stream()
                .map(SecurityEvent::getIpAddress)
                .filter(ip -> ip != null)
                .distinct()
                .count();
            
            if (uniqueIps >= DISTRIBUTED_ATTACK_THRESHOLD) {
                logger.warn("⚠️ DISTRIBUTED SQL INJECTION ATTACK DETECTED from {} IPs", uniqueIps);
            }
            
            // Check for XSS attempts
            List<SecurityEvent> xssEvents = eventRepository
                .findByEventTypeAndTimestampAfter(SecurityEvent.EventType.XSS_ATTEMPT, since);
            
            uniqueIps = xssEvents.stream()
                .map(SecurityEvent::getIpAddress)
                .filter(ip -> ip != null)
                .distinct()
                .count();
            
            if (uniqueIps >= DISTRIBUTED_ATTACK_THRESHOLD) {
                logger.warn("⚠️ DISTRIBUTED XSS ATTACK DETECTED from {} IPs", uniqueIps);
            }
        } catch (Exception e) {
            logger.error("Error detecting distributed attacks: {}", e.getMessage());
        }
    }
    
    /**
     * Detect privilege escalation attempts
     */
    private void detectPrivilegeEscalation(LocalDateTime since) {
        try {
            List<SecurityEvent> escalationEvents = eventRepository
                .findByEventTypeAndTimestampAfter(SecurityEvent.EventType.PRIVILEGE_ESCALATION_ATTEMPT, since);
            
            // Group by user
            Map<String, Long> attemptsByUser = new HashMap<>();
            for (SecurityEvent event : escalationEvents) {
                String username = event.getUsername();
                if (username != null) {
                    attemptsByUser.put(username, attemptsByUser.getOrDefault(username, 0L) + 1);
                }
            }
            
            for (Map.Entry<String, Long> entry : attemptsByUser.entrySet()) {
                if (entry.getValue() >= 3) {
                    logger.warn("⚠️ PRIVILEGE ESCALATION ATTEMPT: User={} Attempts={}", 
                        entry.getKey(), entry.getValue());
                }
            }
        } catch (Exception e) {
            logger.error("Error detecting privilege escalation: {}", e.getMessage());
        }
    }
}
